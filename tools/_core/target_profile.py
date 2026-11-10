"""Target profiles — CUSTOMER-mode engagement configuration (TARGET-PROFILE-V1).

A target profile is a per-user, per-engagement object that describes HOW a
real customer site may be scanned:

  * primary targets + in-scope / out-of-scope patterns (out-of-scope wins)
  * auth configs: a list of roles, each with an auth provider + credentials
    (secrets Fernet-encrypted at rest with VAULT_KEY, never returned decrypted)
  * optional OpenAPI spec, tech-stack notes
  * safety settings: max requests/sec, max concurrency, allowed time window,
    destructive tests allowed (default False)
  * signed authorization record (signer, company, date, scope statement, ack)
  * reporting / branding

LAB mode (no profile_id on the request) is completely unaffected by this
module — nothing here runs unless a scan explicitly carries a profile_id.

Storage: one row per profile in the `target_profiles` table (DDL lives in
tools/auth/_db.py `_SCHEMA_DDL`, idempotent CREATE TABLE IF NOT EXISTS, like
audit_log). Non-secret config is a JSON document; all secrets for all roles
are one Fernet token (`secrets_enc`).

Underscore-prefixed package -> never autoloaded as a tool.
"""
from __future__ import annotations

import copy
import datetime
import fnmatch
import ipaddress
import json
import logging
import re
import socket
import threading
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("vulnuslab.target_profile")

# ── Constants ──────────────────────────────────────────────────────
AUTH_PROVIDERS = ("form_login", "bearer_token", "api_key_header", "cookie",
                  "basic_auth", "oauth2_client_credentials")
# Fields inside an auth role that are secret: encrypted at rest, masked on read.
SECRET_FIELDS = ("password", "token", "api_key", "cookie", "client_secret")
MASK = "********"

MAX_PROFILES_PER_USER = 200
MAX_TARGETS = 100
MAX_PATTERNS = 500
MAX_ROLES = 20
MAX_PATTERN_LEN = 300
MAX_REGEX_LEN = 200
MAX_SPEC_BYTES = 5 * 1024 * 1024
MAX_NOTES = 5000

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,64}$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~\-]{1,100}$")
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

DEFAULT_SAFETY = {
    "max_rps": 10.0,
    "max_concurrency": 8,
    "time_window": None,          # {"timezone","days","start","end"} or None
    "destructive_allowed": False,
    "allow_third_party_intel": True,
    "extra_allowed_hosts": [],
}


class ProfileError(ValueError):
    """Validation error — message is safe to show to the user."""


# ── Secrets (VAULT_KEY Fernet) ─────────────────────────────────────
def _cipher():
    from tools._core.vault import _get_cipher
    return _get_cipher()          # raises RuntimeError if VAULT_KEY unset


def encrypt_secrets(secrets: dict) -> Optional[str]:
    if not secrets:
        return None
    return _cipher().encrypt(json.dumps(secrets).encode()).decode()


def decrypt_secrets(token: Optional[str]) -> dict:
    if not token:
        return {}
    return json.loads(_cipher().decrypt(token.encode()).decode())


# ── Validation / normalisation (pure python, testable offline) ──────
def _clean_str(v, field: str, max_len: int, required: bool = False,
               allow_newlines: bool = False) -> str:
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise ProfileError(f"{field} must be a string")
    v = v.strip()
    if required and not v:
        raise ProfileError(f"{field} is required")
    if len(v) > max_len:
        raise ProfileError(f"{field} exceeds {max_len} characters")
    check = v.replace("\n", "").replace("\r", "").replace("\t", "") if allow_newlines else v
    if _CTRL_RE.search(check):
        raise ProfileError(f"{field} contains control characters")
    return v


def _clean_list(v, field: str, max_items: int, max_len: int = MAX_PATTERN_LEN) -> list:
    if v is None:
        return []
    if not isinstance(v, list):
        raise ProfileError(f"{field} must be a list")
    if len(v) > max_items:
        raise ProfileError(f"{field} has more than {max_items} entries")
    out = []
    for i, item in enumerate(v):
        s = _clean_str(item, f"{field}[{i}]", max_len)
        if not s:
            continue
        if any(c.isspace() for c in s):
            raise ProfileError(f"{field}[{i}] must not contain whitespace")
        if s not in out:
            out.append(s)
    return out


def _as_int(v, default: int) -> int:
    try:
        return int(v) if v not in (None, "") else default
    except Exception:
        raise ProfileError(f"expected an integer, got {v!r}")


def _validate_pattern(p: str, field: str) -> None:
    if p.startswith("re:"):
        rx = p[3:]
        if not rx or len(rx) > MAX_REGEX_LEN:
            raise ProfileError(f"{field}: regex must be 1..{MAX_REGEX_LEN} chars")
        try:
            re.compile(rx)
        except re.error as e:
            raise ProfileError(f"{field}: invalid regex ({e})")


def _validate_time_window(tw) -> Optional[dict]:
    if not tw:
        return None
    if not isinstance(tw, dict):
        raise ProfileError("safety.time_window must be an object")
    tz = _clean_str(tw.get("timezone") or "UTC", "time_window.timezone", 64)
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(tz)
    except Exception:
        raise ProfileError(f"time_window.timezone {tz!r} is not a valid IANA zone")
    days = tw.get("days") or list(_DAYS)
    if not isinstance(days, list) or not days:
        raise ProfileError("time_window.days must be a non-empty list")
    days = [str(d).strip().lower()[:3] for d in days]
    for d in days:
        if d not in _DAYS:
            raise ProfileError(f"time_window.days: unknown day {d!r}")
    start = str(tw.get("start") or "00:00").strip()
    end = str(tw.get("end") or "23:59").strip()
    for lbl, val in (("start", start), ("end", end)):
        if not _HHMM_RE.match(val):
            raise ProfileError(f"time_window.{lbl} must be HH:MM (24h)")
    return {"timezone": tz, "days": sorted(set(days), key=_DAYS.index),
            "start": start, "end": end}


def _validate_safety(s) -> dict:
    out = copy.deepcopy(DEFAULT_SAFETY)
    if s is None:
        return out
    if not isinstance(s, dict):
        raise ProfileError("safety must be an object")
    if s.get("max_rps") is not None:
        try:
            rps = float(s["max_rps"])
        except Exception:
            raise ProfileError("safety.max_rps must be a number")
        if not (0.1 <= rps <= 1000):
            raise ProfileError("safety.max_rps must be between 0.1 and 1000")
        out["max_rps"] = rps
    if s.get("max_concurrency") is not None:
        try:
            mc = int(s["max_concurrency"])
        except Exception:
            raise ProfileError("safety.max_concurrency must be an integer")
        if not (1 <= mc <= 32):
            raise ProfileError("safety.max_concurrency must be between 1 and 32")
        out["max_concurrency"] = mc
    out["time_window"] = _validate_time_window(s.get("time_window"))
    out["destructive_allowed"] = bool(s.get("destructive_allowed", False))
    out["allow_third_party_intel"] = bool(s.get("allow_third_party_intel", True))
    out["extra_allowed_hosts"] = _clean_list(s.get("extra_allowed_hosts"),
                                             "safety.extra_allowed_hosts", 100, 253)
    return out


def _validate_authorization(a) -> dict:
    a = a or {}
    if not isinstance(a, dict):
        raise ProfileError("authorization must be an object")
    out = {
        "signer_name": _clean_str(a.get("signer_name"), "authorization.signer_name", 200),
        "signer_company": _clean_str(a.get("signer_company"), "authorization.signer_company", 200),
        "signer_email": _clean_str(a.get("signer_email"), "authorization.signer_email", 254),
        "signed_date": _clean_str(a.get("signed_date"), "authorization.signed_date", 10),
        "valid_until": _clean_str(a.get("valid_until"), "authorization.valid_until", 10),
        "scope_statement": _clean_str(a.get("scope_statement"), "authorization.scope_statement",
                                      5000, allow_newlines=True),
        "ack": bool(a.get("ack", False)),
    }
    for f in ("signed_date", "valid_until"):
        if out[f]:
            try:
                datetime.date.fromisoformat(out[f])
            except Exception:
                raise ProfileError(f"authorization.{f} must be YYYY-MM-DD")
    if out["ack"]:
        missing = [k for k in ("signer_name", "signer_company", "signed_date", "scope_statement")
                   if not out[k]]
        if missing:
            raise ProfileError("authorization.ack requires: " + ", ".join(missing))
    return out


def _validate_indicator(ind) -> Optional[dict]:
    if not ind:
        return None
    if not isinstance(ind, dict):
        raise ProfileError("logged_in_indicator must be an object")
    out = {
        "url": _clean_str(ind.get("url"), "logged_in_indicator.url", 500),
        "regex": _clean_str(ind.get("regex"), "logged_in_indicator.regex", MAX_REGEX_LEN),
        "negative_regex": _clean_str(ind.get("negative_regex"),
                                     "logged_in_indicator.negative_regex", MAX_REGEX_LEN),
        "check_interval_sec": _as_int(ind.get("check_interval_sec"), 300),
    }
    for k in ("regex", "negative_regex"):
        if out[k]:
            try:
                re.compile(out[k])
            except re.error as e:
                raise ProfileError(f"logged_in_indicator.{k}: invalid regex ({e})")
    out["check_interval_sec"] = max(30, min(out["check_interval_sec"], 3600))
    return out


_ROLE_PUBLIC_FIELDS = {
    # provider -> (required non-secret fields, required secret fields)
    "form_login": (("login_url", "username"), ("password",)),
    "bearer_token": ((), ("token",)),
    "api_key_header": (("header_name",), ("api_key",)),
    "cookie": ((), ("cookie",)),
    "basic_auth": (("username",), ("password",)),
    "oauth2_client_credentials": (("token_url", "client_id"), ("client_secret",)),
}


def _validate_role(r, idx: int, existing_secrets: dict) -> tuple[dict, dict]:
    """Return (public_role_dict, secret_dict) for one role. A secret value equal
    to MASK (or absent) keeps the previously stored secret for that role."""
    if not isinstance(r, dict):
        raise ProfileError(f"auth_configs[{idx}] must be an object")
    name = _clean_str(r.get("role"), f"auth_configs[{idx}].role", 64, required=True)
    if not _ROLE_NAME_RE.match(name):
        raise ProfileError(f"auth_configs[{idx}].role has invalid characters")
    provider = _clean_str(r.get("provider"), f"auth_configs[{idx}].provider", 40, required=True)
    if provider not in AUTH_PROVIDERS:
        raise ProfileError(f"auth_configs[{idx}].provider must be one of {', '.join(AUTH_PROVIDERS)}")
    pub = {
        "role": name, "provider": provider,
        "username": _clean_str(r.get("username"), "username", 254),
        "login_url": _clean_str(r.get("login_url"), "login_url", 500),
        "username_field": _clean_str(r.get("username_field"), "username_field", 100),
        "password_field": _clean_str(r.get("password_field"), "password_field", 100),
        "success_text": _clean_str(r.get("success_text"), "success_text", 200),
        "header_name": _clean_str(r.get("header_name"), "header_name", 100),
        "token_url": _clean_str(r.get("token_url"), "token_url", 500),
        "client_id": _clean_str(r.get("client_id"), "client_id", 300),
        "oauth_scope": _clean_str(r.get("oauth_scope"), "oauth_scope", 500),
        "audience": _clean_str(r.get("audience"), "audience", 500),
        "session_ttl_sec": max(60, min(_as_int(r.get("session_ttl_sec"), 1800), 86400)),
        "logged_in_indicator": _validate_indicator(r.get("logged_in_indicator")),
    }
    extra = r.get("extra_fields") or {}
    if not isinstance(extra, dict) or len(extra) > 30:
        raise ProfileError(f"auth_configs[{idx}].extra_fields must be an object (<=30 keys)")
    pub["extra_fields"] = {_clean_str(k, "extra_fields key", 100): _clean_str(str(v), "extra_fields value", 500)
                           for k, v in extra.items()}
    hdrs = r.get("extra_headers") or {}
    if not isinstance(hdrs, dict) or len(hdrs) > 20:
        raise ProfileError(f"auth_configs[{idx}].extra_headers must be an object (<=20 keys)")
    pub["extra_headers"] = {}
    for k, v in hdrs.items():
        k = _clean_str(k, "extra_headers name", 100)
        if not _HEADER_NAME_RE.match(k) or k.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise ProfileError(f"extra_headers: header {k!r} not allowed")
        pub["extra_headers"][k] = _clean_str(str(v), "extra_headers value", 2000)
    if pub["header_name"] and not _HEADER_NAME_RE.match(pub["header_name"]):
        raise ProfileError(f"auth_configs[{idx}].header_name is not a valid header name")

    prev = existing_secrets.get(name) or {}
    sec = {}
    for f in SECRET_FIELDS:
        v = r.get(f)
        if v is None or v == MASK:
            if prev.get(f):
                sec[f] = prev[f]
            continue
        v = _clean_str(v, f"auth_configs[{idx}].{f}", 8000)
        if v:
            sec[f] = v
    req_pub, req_sec = _ROLE_PUBLIC_FIELDS[provider]
    for f in req_pub:
        if not pub.get(f):
            raise ProfileError(f"auth_configs[{idx}] ({provider}) requires {f}")
    for f in req_sec:
        if not sec.get(f):
            raise ProfileError(f"auth_configs[{idx}] ({provider}) requires {f}")
    return pub, sec


def normalize_profile(data: dict, existing: Optional[dict] = None,
                      existing_secrets: Optional[dict] = None) -> tuple[dict, dict]:
    """Validate an incoming profile document. Returns (config, secrets_by_role).

    `existing` / `existing_secrets` let an update omit or mask secrets and keep
    what is stored. Raises ProfileError with a user-safe message."""
    if not isinstance(data, dict):
        raise ProfileError("profile body must be an object")
    existing = existing or {}
    existing_secrets = existing_secrets or {}

    name = _clean_str(data.get("name", existing.get("name")), "name", 120, required=True)
    targets = _clean_list(data.get("primary_targets", existing.get("primary_targets")),
                          "primary_targets", MAX_TARGETS)
    if not targets:
        raise ProfileError("primary_targets must contain at least one URL/host/CIDR")
    in_scope = _clean_list(data.get("in_scope", existing.get("in_scope")), "in_scope", MAX_PATTERNS)
    out_scope = _clean_list(data.get("out_of_scope", existing.get("out_of_scope")),
                            "out_of_scope", MAX_PATTERNS)
    for lbl, lst in (("in_scope", in_scope), ("out_of_scope", out_scope)):
        for i, p in enumerate(lst):
            _validate_pattern(p, f"{lbl}[{i}]")

    roles_in = data.get("auth_configs", None)
    roles, secrets = [], {}
    if roles_in is None:
        roles = existing.get("auth_configs") or []
        secrets = {k: v for k, v in existing_secrets.items()
                   if any(r["role"] == k for r in roles)}
    else:
        if not isinstance(roles_in, list) or len(roles_in) > MAX_ROLES:
            raise ProfileError(f"auth_configs must be a list of <= {MAX_ROLES} roles")
        for i, r in enumerate(roles_in):
            pub, sec = _validate_role(r, i, existing_secrets)
            if any(x["role"] == pub["role"] for x in roles):
                raise ProfileError(f"duplicate role name {pub['role']!r}")
            roles.append(pub)
            if sec:
                secrets[pub["role"]] = sec

    default_role = _clean_str(data.get("default_role", existing.get("default_role")),
                              "default_role", 64)
    if default_role and not any(r["role"] == default_role for r in roles):
        raise ProfileError("default_role must name one of auth_configs")

    reporting_in = data.get("reporting", existing.get("reporting")) or {}
    if not isinstance(reporting_in, dict):
        raise ProfileError("reporting must be an object")
    reporting = {
        "company_name": _clean_str(reporting_in.get("company_name"), "reporting.company_name", 200),
        # logo_path is server-controlled (set only by the logo upload endpoint)
        "logo_path": (existing.get("reporting") or {}).get("logo_path") or "",
    }

    openapi_in = data.get("openapi", existing.get("openapi")) or {}
    if not isinstance(openapi_in, dict):
        raise ProfileError("openapi must be an object")
    openapi = {
        "source_url": _clean_str(openapi_in.get("source_url"), "openapi.source_url", 1000),
        # spec text is stored via the dedicated endpoint; keep existing meta
        "has_spec": bool((existing.get("openapi") or {}).get("has_spec")),
        "spec_sha256": (existing.get("openapi") or {}).get("spec_sha256") or "",
        "uploaded_at": (existing.get("openapi") or {}).get("uploaded_at") or "",
    }

    cfg = {
        "name": name,
        "primary_targets": targets,
        "in_scope": in_scope,
        "out_of_scope": out_scope,
        "auth_configs": roles,
        "default_role": default_role,
        "openapi": openapi,
        "tech_stack_notes": _clean_str(data.get("tech_stack_notes", existing.get("tech_stack_notes")),
                                       "tech_stack_notes", MAX_NOTES, allow_newlines=True),
        "safety": _validate_safety(data.get("safety", existing.get("safety"))),
        "authorization": _validate_authorization(data.get("authorization", existing.get("authorization"))),
        "reporting": reporting,
    }
    return cfg, secrets


def mask_config(cfg: dict, secrets: dict) -> dict:
    """Public view: every secret replaced with MASK + a has_<field> flag."""
    out = copy.deepcopy(cfg)
    for r in out.get("auth_configs") or []:
        sec = secrets.get(r["role"]) or {}
        for f in SECRET_FIELDS:
            r[f] = MASK if sec.get(f) else None
            r[f"has_{f}"] = bool(sec.get(f))
    return out


# ── Scope matching ─────────────────────────────────────────────────
_DNS_CACHE: dict = {}
_DNS_TTL = 300.0
_DNS_LOCK = threading.Lock()


def _resolve(host: str) -> list:
    now = time.monotonic()
    with _DNS_LOCK:
        hit = _DNS_CACHE.get(host)
        if hit and now - hit[0] < _DNS_TTL:
            return hit[1]
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        ips = []
    with _DNS_LOCK:
        _DNS_CACHE[host] = (now, ips)
    return ips


def _parse_url(url: str):
    u = url if "://" in url else "http://" + url
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except Exception:
        return None
    if not host:
        return None
    scheme = (p.scheme or "http").lower()
    if port is None:
        port = 443 if scheme in ("https", "wss") else 80
    return {"scheme": scheme, "host": host, "port": port, "path": p.path or "/", "url": u}


def _ip_of(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except Exception:
        return None


class _Pattern:
    """One compiled scope pattern. Kinds:
       re:<regex>                  regex search on the full URL
       10.0.0.0/24 | 10.0.0.5      CIDR / IP (hostnames are resolved)
       https://h.example.com/api   URL prefix (host may be a glob)
       *.example.com[:443][/path]  host glob, optional port + path prefix
    """
    __slots__ = ("raw", "kind", "rx", "net", "scheme", "host", "port", "path")

    def __init__(self, raw: str, host_only: bool = False):
        self.raw = raw
        self.rx = self.net = self.scheme = self.host = self.port = None
        self.path = "/"
        if raw.startswith("re:"):
            self.kind = "regex"
            self.rx = re.compile(raw[3:], re.I)
            return
        try:
            self.net = ipaddress.ip_network(raw, strict=False)
            self.kind = "cidr"
            return
        except Exception:
            pass
        s = raw
        if "://" in s:
            self.scheme = s.split("://", 1)[0].lower()
            s = s.split("://", 1)[1]
        hostport, _, path = s.partition("/")
        self.path = "/" + path if path and not host_only else "/"
        if hostport.startswith("[") and "]" in hostport:          # [v6]:port
            h, _, rest = hostport[1:].partition("]")
            self.host = h.lower()
            if rest.startswith(":") and rest[1:].isdigit():
                self.port = int(rest[1:])
        elif hostport.count(":") == 1:
            h, _, prt = hostport.partition(":")
            self.host = h.lower()
            if prt.isdigit() and not host_only:
                self.port = int(prt)
        else:
            self.host = hostport.lower()
        self.host = (self.host or "").rstrip(".")
        if host_only:
            self.scheme = None
        self.kind = "host"
        ipv = _ip_of(self.host)
        if ipv is not None:   # bare IP with port/path -> treat host as /32 network
            self.net = ipaddress.ip_network(str(ipv))

    def matches(self, u: dict, resolve: bool = True, any_ip: bool = True) -> bool:
        if self.kind == "regex":
            return bool(self.rx.search(u["url"][:2048]))
        if self.kind == "cidr":
            return self._ip_match(u["host"], resolve, any_ip)
        # host kind
        if self.scheme and self.scheme != u["scheme"]:
            return False
        if self.port and self.port != u["port"]:
            return False
        if self.net is not None:
            if not self._ip_match(u["host"], resolve, any_ip):
                return False
        elif not fnmatch.fnmatchcase(u["host"], self.host):
            return False
        if self.path and self.path != "/":
            p = u["path"] or "/"
            base = self.path.rstrip("/")
            if not (p == base or p.startswith(base + "/") or p.startswith(self.path)):
                return False
        return True

    def _ip_match(self, host: str, resolve: bool, any_ip: bool) -> bool:
        ip = _ip_of(host)
        ips = [ip] if ip is not None else (
            [x for x in (_ip_of(a) for a in _resolve(host)) if x is not None] if resolve else [])
        if not ips:
            return False
        hits = [i in self.net for i in ips]
        return any(hits) if any_ip else all(hits)


# Registrable-domain heuristic for "is this host customer-related?"
_MULTI_SLD = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
              "co.in", "com.br", "co.jp", "co.nz", "com.sg", "co.za", "com.mx", "co.id"}


def registrable_domain(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if _ip_of(host) is not None:
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class ScopeRules:
    """Compiled scope for one profile. decide(url) -> (allowed, reason).

    Semantics:
      * out_of_scope patterns are checked first and always win. For CIDR
        patterns a hostname is blocked if ANY resolved address is inside.
      * in-scope = primary_targets (host-level) + in_scope patterns. A
        hostname matches an in-scope CIDR only if ALL resolved addresses are
        inside it (so DNS can't smuggle a request outside the range).
    """

    def __init__(self, cfg: dict):
        self.out = [_Pattern(p) for p in (cfg.get("out_of_scope") or [])]
        self.inc = [_Pattern(p) for p in (cfg.get("in_scope") or [])]
        self.inc += [_Pattern(t, host_only=True) for t in (cfg.get("primary_targets") or [])]
        doms = set()
        for p in self.inc + self.out:
            if p.kind == "host" and p.host:
                doms.add(registrable_domain(p.host.replace("*.", "").replace("*", "")))
        self.customer_domains = {d for d in doms if d}

    def decide(self, url: str, resolve: bool = True) -> tuple[bool, str]:
        u = _parse_url(url)
        if u is None:
            return False, "unparseable URL"
        for p in self.out:
            if p.matches(u, resolve=resolve, any_ip=True):
                return False, f"matches out-of-scope pattern {p.raw!r}"
        for p in self.inc:
            if p.matches(u, resolve=resolve, any_ip=False):
                return True, f"matches in-scope {p.raw!r}"
        return False, "not covered by any in-scope pattern or primary target"

    def target_in_scope(self, target: str) -> tuple[bool, str]:
        """Scope check for a scan TARGET, which may also be a CIDR range."""
        t = (target or "").strip()
        if "/" in t and "://" not in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except Exception:
                net = None
            if net is not None and net.num_addresses > 1:
                for p in self.out:
                    if p.kind == "cidr" and net.overlaps(p.net):
                        return False, (f"range overlaps out-of-scope {p.raw!r} (split the range so "
                                       f"it excludes that address)")
                for p in self.inc:
                    if p.kind == "cidr" and net.version == p.net.version and net.subnet_of(p.net):
                        return True, f"range inside in-scope {p.raw!r}"
                return False, "range not inside any in-scope CIDR"
        return self.decide(t)

    def is_customer_related(self, url: str) -> bool:
        u = _parse_url(url)
        if u is None:
            return True
        if _ip_of(u["host"]) is not None:
            return True          # raw IPs are always treated as potential customer assets
        return registrable_domain(u["host"]) in self.customer_domains


# ── Time window / authorization coverage ───────────────────────────
def within_time_window(tw: Optional[dict], now: Optional[datetime.datetime] = None) -> bool:
    if not tw:
        return True
    from zoneinfo import ZoneInfo
    now = now or datetime.datetime.now(datetime.timezone.utc)
    local = now.astimezone(ZoneInfo(tw.get("timezone") or "UTC"))
    hm = local.strftime("%H:%M")
    day = _DAYS[local.weekday()]
    prev_day = _DAYS[(local.weekday() - 1) % 7]
    start, end = tw.get("start", "00:00"), tw.get("end", "23:59")
    days = tw.get("days") or list(_DAYS)
    if start <= end:
        return day in days and start <= hm <= end
    # overnight window, e.g. 22:00 -> 06:00 : the early-morning part belongs
    # to the window that STARTED on the previous day.
    if hm >= start:
        return day in days
    if hm <= end:
        return prev_day in days
    return False


def authorization_status(cfg: dict, target: Optional[str] = None,
                         today: Optional[datetime.date] = None) -> tuple[bool, str]:
    """(ok, reason): is there a signed authorization record that covers target?"""
    a = cfg.get("authorization") or {}
    if not a.get("ack"):
        return False, "profile has no acknowledged authorization record"
    for k in ("signer_name", "signer_company", "signed_date", "scope_statement"):
        if not a.get(k):
            return False, f"authorization record missing {k}"
    today = today or datetime.datetime.utcnow().date()
    try:
        if datetime.date.fromisoformat(a["signed_date"]) > today:
            return False, "authorization signed_date is in the future"
        if a.get("valid_until") and datetime.date.fromisoformat(a["valid_until"]) < today:
            return False, "authorization has expired (valid_until passed)"
    except Exception:
        return False, "authorization dates are invalid"
    if target:
        ok, why = ScopeRules(cfg).target_in_scope(target)
        if not ok:
            return False, f"target is outside the authorized scope ({why})"
    return True, f"signed by {a['signer_name']} ({a['signer_company']}) on {a['signed_date']}"


# ── DB layer ───────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _row_to_record(row: dict) -> dict:
    cfg = json.loads(row.get("config") or "{}")
    return {"id": row["id"], "owner_id": row["owner_id"], "config": cfg,
            "secrets_enc": row.get("secrets_enc"),
            "created_at": row.get("created_at"), "updated_at": row.get("updated_at")}


def public_view(rec: dict) -> dict:
    try:
        secrets = decrypt_secrets(rec.get("secrets_enc"))
    except Exception:
        secrets = {}
    out = mask_config(rec["config"], secrets)
    out.update({"id": rec["id"], "owner_id": rec["owner_id"],
                "created_at": rec["created_at"], "updated_at": rec["updated_at"]})
    ok, why = authorization_status(rec["config"])
    out["authorization_status"] = {"ok": ok, "reason": why}
    return out


def _get_db():
    from tools.auth._db import get_db
    return get_db()


def create_profile(owner_id: str, data: dict) -> dict:
    cfg, secrets = normalize_profile(data)
    enc = encrypt_secrets(secrets) if secrets else None
    pid = str(uuid.uuid4())
    now = _now()
    with _get_db() as con:
        n = con.execute("SELECT COUNT(*) AS n FROM target_profiles WHERE owner_id=?",
                        (owner_id,)).fetchone()
        if n and int(n["n"]) >= MAX_PROFILES_PER_USER:
            raise ProfileError(f"profile limit reached ({MAX_PROFILES_PER_USER})")
        con.execute(
            "INSERT INTO target_profiles (id, owner_id, name, config, secrets_enc, "
            "openapi_spec, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (pid, owner_id, cfg["name"], json.dumps(cfg), enc, None, now, now))
    return {"id": pid, "owner_id": owner_id, "config": cfg, "secrets_enc": enc,
            "created_at": now, "updated_at": now}


def get_profile_record(profile_id: str, owner_id: Optional[str]) -> Optional[dict]:
    """Fetch one profile. owner_id=None is ONLY for admin reads; every user
    path passes the authenticated user id so the row must belong to them."""
    if not profile_id or not isinstance(profile_id, str) or len(profile_id) > 64:
        return None
    sql = ("SELECT id, owner_id, config, secrets_enc, created_at, updated_at "
           "FROM target_profiles WHERE id=?")
    params: tuple = (profile_id,)
    if owner_id is not None:
        sql += " AND owner_id=?"
        params = (profile_id, owner_id)
    with _get_db() as con:
        row = con.execute(sql, params).fetchone()
    return _row_to_record(row) if row else None


def list_profiles(owner_id: Optional[str], limit: int = 100, offset: int = 0) -> list:
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    sql = "SELECT id, owner_id, config, secrets_enc, created_at, updated_at FROM target_profiles"
    params: tuple = ()
    if owner_id is not None:
        sql += " WHERE owner_id=?"
        params = (owner_id,)
    sql += f" ORDER BY updated_at DESC LIMIT {limit} OFFSET {offset}"
    with _get_db() as con:
        rows = con.execute(sql, params).fetchall()
    return [_row_to_record(r) for r in rows]


def update_profile(profile_id: str, owner_id: str, data: dict, partial: bool = True) -> Optional[dict]:
    rec = get_profile_record(profile_id, owner_id)
    if rec is None:
        return None
    existing_secrets = decrypt_secrets(rec.get("secrets_enc"))
    base = rec["config"] if partial else {
        # full replace: only server-controlled fields carry over
        "reporting": {"logo_path": (rec["config"].get("reporting") or {}).get("logo_path")},
        "openapi": rec["config"].get("openapi"),
    }
    cfg, secrets = normalize_profile(data, existing=base, existing_secrets=existing_secrets)
    enc = encrypt_secrets(secrets) if secrets else None
    now = _now()
    with _get_db() as con:
        con.execute("UPDATE target_profiles SET name=?, config=?, secrets_enc=?, updated_at=? "
                    "WHERE id=? AND owner_id=?",
                    (cfg["name"], json.dumps(cfg), enc, now, profile_id, owner_id))
    invalidate(profile_id)
    rec.update(config=cfg, secrets_enc=enc, updated_at=now)
    return rec


def delete_profile(profile_id: str, owner_id: Optional[str]) -> bool:
    sql, params = "DELETE FROM target_profiles WHERE id=?", (profile_id,)
    if owner_id is not None:
        sql += " AND owner_id=?"
        params = (profile_id, owner_id)
    with _get_db() as con:
        n = con.execute(sql, params).rowcount
    invalidate(profile_id)
    return bool(n)


def set_server_fields(profile_id: str, owner_id: str, *, logo_path: Optional[str] = None,
                      spec_text: Optional[str] = None, spec_meta: Optional[dict] = None) -> bool:
    rec = get_profile_record(profile_id, owner_id)
    if rec is None:
        return False
    cfg = rec["config"]
    now = _now()
    if logo_path is not None:
        cfg.setdefault("reporting", {})["logo_path"] = logo_path
    if spec_meta is not None:
        cfg.setdefault("openapi", {}).update(spec_meta)
    with _get_db() as con:
        if spec_text is not None:
            con.execute("UPDATE target_profiles SET config=?, openapi_spec=?, updated_at=? "
                        "WHERE id=? AND owner_id=?",
                        (json.dumps(cfg), spec_text, now, profile_id, owner_id))
        else:
            con.execute("UPDATE target_profiles SET config=?, updated_at=? WHERE id=? AND owner_id=?",
                        (json.dumps(cfg), now, profile_id, owner_id))
    invalidate(profile_id)
    return True


def get_openapi_spec(profile_id: str, owner_id: str) -> Optional[str]:
    with _get_db() as con:
        row = con.execute("SELECT openapi_spec FROM target_profiles WHERE id=? AND owner_id=?",
                          (profile_id, owner_id)).fetchone()
    return (row or {}).get("openapi_spec")


# ── Runtime cache (decrypted, in-memory only) ──────────────────────
class RuntimeProfile:
    """What the scan pipeline needs: config, decrypted secrets, compiled scope."""
    __slots__ = ("id", "owner_id", "cfg", "secrets", "scope", "loaded_at")

    def __init__(self, rec: dict):
        self.id = rec["id"]
        self.owner_id = rec["owner_id"]
        self.cfg = rec["config"]
        self.secrets = decrypt_secrets(rec.get("secrets_enc"))
        self.scope = ScopeRules(self.cfg)
        self.loaded_at = time.monotonic()

    @property
    def safety(self) -> dict:
        return self.cfg.get("safety") or DEFAULT_SAFETY

    def role(self, name: Optional[str] = None) -> Optional[dict]:
        roles = self.cfg.get("auth_configs") or []
        if not roles:
            return None
        name = name or self.cfg.get("default_role") or roles[0]["role"]
        for r in roles:
            if r["role"] == name:
                merged = dict(r)
                merged.update(self.secrets.get(r["role"]) or {})
                return merged
        return None


_RT_CACHE: dict = {}
_RT_TTL = 30.0
_RT_LOCK = threading.Lock()


def get_runtime_profile(profile_id: str, owner_id: str) -> Optional[RuntimeProfile]:
    """Cached (30s) decrypted profile for scans. Ownership is ALWAYS checked
    against owner_id — the cache key includes it, so a cached entry for user A
    can never satisfy a lookup by user B."""
    if not profile_id or not owner_id:
        return None
    key = (profile_id, owner_id)
    now = time.monotonic()
    with _RT_LOCK:
        hit = _RT_CACHE.get(key)
        if hit and now - hit.loaded_at < _RT_TTL:
            return hit
    rec = get_profile_record(profile_id, owner_id)
    if rec is None:
        return None
    rt = RuntimeProfile(rec)
    with _RT_LOCK:
        _RT_CACHE[key] = rt
    return rt


def invalidate(profile_id: str) -> None:
    with _RT_LOCK:
        for k in [k for k in _RT_CACHE if k[0] == profile_id]:
            _RT_CACHE.pop(k, None)
    try:
        from tools._core.session_manager import invalidate_profile_sessions
        invalidate_profile_sessions(profile_id)
    except Exception:
        pass
