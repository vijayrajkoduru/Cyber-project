"""Shared infrastructure used by every tool.

Pattern: import what you need from `tools._shared` and write a single
register(app) function in your tool file. Examples:

    from tools._shared import (
        ScanRequest, verify_token, verify_scan_quota,
        safe_get, safe_post, wrap_finding,
    )
"""
import os
import re
import sys
import hmac
import hashlib
import logging
import time
import uuid
import random
import string
import asyncio
import datetime
import contextvars
from typing import Optional, List

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt as _jwt
import requests as _req_lib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("vulnuslab.shared")

# ── JWT auth ────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
bearer = HTTPBearer(auto_error=False)

# Context-vars so tools deep in the stack can read the current request's
# auth without threading it through every function arg.
_AUTH_CTX: contextvars.ContextVar = contextvars.ContextVar("auth_ctx", default=None)
_USER_CTX: contextvars.ContextVar = contextvars.ContextVar("user_ctx", default=None)


class ScanRequest(BaseModel):
    """Standard request shape every tool accepts.
    Tools that need extra fields subclass this in their own file.

    Extended 2026-06-01: optional customer-input fields for Container/K8s
    module probes that need more than a hostname. Each field is consumed
    by specific probes via a precondition gate; if absent the probe
    honestly returns NOT_APPLICABLE."""
    target: str
    api_key: Optional[str] = None
    auth_cookie: Optional[str] = None       # e.g. "PHPSESSID=abc; token=xyz"
    auth_bearer: Optional[str] = None       # e.g. "eyJhbGci..."
    wordlist: Optional[List[str]] = None    # custom paths for fuzzers
    # Customer-provided artifacts for input-required scanners:
    image_ref: Optional[str] = None         # OCI image ref e.g. "nginx:1.21"
    dockerfile_text: Optional[str] = None   # raw Dockerfile content
    kubeconfig: Optional[str] = None        # full kubeconfig YAML
    pod_spec_yaml: Optional[str] = None     # K8s pod / deployment spec YAML
    repo_url: Optional[str] = None          # git repository URL (Supply Chain)
    api_spec_url: Optional[str] = None      # OpenAPI / Swagger spec URL (APISec)


def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    """Decode JWT. Raises 401 if missing/invalid. Every tool endpoint
    that requires auth depends on this."""
    if not creds:
        raise HTTPException(401, "Missing Authorization header")
    try:
        payload = _jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        log.warning("JWT decode failed: %s", e)
        raise HTTPException(401, "Invalid or expired token")
    _USER_CTX.set(payload.get("sub", "unknown"))
    return payload


INTERNAL_FANOUT_HEADER = "x-vl-internal-fanout"


def _derive_internal_fanout_token() -> str:
    """Secret that marks a request as internal orchestrator fan-out (so one
    user scan fanning out to N scanners counts as 1 unit, not N). An explicit
    VL_INTERNAL_FANOUT_TOKEN wins; otherwise derive it from JWT_SECRET so all
    uvicorn workers agree WITHOUT shipping a public default. The old hardcoded
    "vlforge-internal" was committed to the repo, so anyone could forge the
    marker and bypass quota; JWT_SECRET is per-deployment and secret (main.py
    refuses to boot without it)."""
    explicit = os.getenv("VL_INTERNAL_FANOUT_TOKEN", "").strip()
    if explicit:
        return explicit
    seed = (JWT_SECRET or "").encode()
    if not seed:
        # No JWT_SECRET (e.g. a bare unit-test import). Random per process —
        # safe because there is no real cross-worker fan-out to authenticate.
        seed = os.urandom(32)
    return hmac.new(seed, b"vl-internal-fanout-v1", hashlib.sha256).hexdigest()


INTERNAL_FANOUT_TOKEN = _derive_internal_fanout_token()

# Back-compat aliases — internal callers referenced the underscore names.
_INTERNAL_FANOUT_HEADER = INTERNAL_FANOUT_HEADER
_INTERNAL_FANOUT_TOKEN = INTERNAL_FANOUT_TOKEN
_INTERNAL_TRUSTED_IPS = ("127.0.0.1", "::1", "localhost")
_INTERNAL_TRUSTED_PREFIXES = ("10.", "172.", "192.168.")


def is_internal_fanout(request: Optional[Request]) -> bool:
    """VL-PRIME: True iff this request is signed orchestrator fan-out
    from a trusted internal IP. The orchestrator stamps every internal
    HTTP fan-out with VL_INTERNAL_FANOUT_TOKEN; the limiter then knows
    that one user scan triggering N internal calls counts as 1, not N."""
    if request is None:
        return False
    if request.headers.get(_INTERNAL_FANOUT_HEADER, "") != _INTERNAL_FANOUT_TOKEN:
        return False
    client_ip = request.client.host if request.client else ""
    if client_ip in _INTERNAL_TRUSTED_IPS:
        return True
    return any(client_ip.startswith(p) for p in _INTERNAL_TRUSTED_PREFIXES)


def verify_scan_quota(request: Request, payload=Depends(verify_token)):
    """VL-PRIME: verify_token + per-plan quota check. Internal orchestrator
    fan-out (signed marker from 127.0.0.1/172.x/10.x/192.168.x) bypasses
    quota counting so one user scan that fans out to N scanners costs 1
    unit, not N. Without this exemption the limiter 429's most scanners."""
    if is_internal_fanout(request):
        return payload
    # TODO: per-plan quota check when billing module is wired
    return payload


def verify_admin(payload=Depends(verify_token)):
    """Admin-only gate. Use on every /api/admin/* endpoint.
    Raises 403 if the JWT does not carry role='admin'."""
    if payload.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin role required")
    return payload


# ── HTTP helper — Trust-First (adaptive timeout + retry + 429-aware) ──
_BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
                   "Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}


# ── WAF / CDN detection ──────────────────────────────────────────────
# When a target is fronted by a WAF, aggressive scanners (gobuster, nuclei,
# force_browse) get blocked after a few hundred requests. We detect the WAF
# vendor early so individual scanners can:
#   - Slow down (sleep between requests)
#   - Skip cleanly with a clear "blocked by WAF" message
#   - Avoid false positives (e.g. cert chain validation on CDN)
# Cache results per-target for the duration of a scan (1 probe = full scan).
_WAF_CACHE: dict[str, dict] = {}


def detect_waf(url: str, *, req=None) -> dict:
    """One-shot HEAD probe to detect WAF/CDN. Returns {'vendor': str, 'detected': bool}.
    Cached per-host so subsequent scanners don't re-probe.
    Idempotent on failure — returns {'vendor': None, 'detected': False, 'reason': ...}.
    """
    from urllib.parse import urlparse
    host = urlparse(url).netloc or url
    if host in _WAF_CACHE:
        return _WAF_CACHE[host]
    result = {"vendor": None, "detected": False, "host": host}
    try:
        r = _req_lib.head(url, timeout=8, allow_redirects=True,
                          headers=_BROWSER_HEADERS, verify=False)
        h = {k.lower(): v.lower() for k, v in r.headers.items()}
        server = h.get("server", "")
        if "cloudflare" in server or "cf-ray" in h or h.get("cf-cache-status"):
            result.update(vendor="Cloudflare", detected=True)
        elif "akamai" in server or h.get("x-akamai-transformed"):
            result.update(vendor="Akamai", detected=True)
        elif "awselb" in server or "cloudfront" in server or h.get("x-amz-cf-id"):
            result.update(vendor="AWS CloudFront", detected=True)
        elif "fastly" in server or h.get("fastly-debug-digest"):
            result.update(vendor="Fastly", detected=True)
        elif "imperva" in server or "incap_ses" in h.get("set-cookie", ""):
            result.update(vendor="Imperva", detected=True)
        elif "sucuri" in server or h.get("x-sucuri-id"):
            result.update(vendor="Sucuri", detected=True)
        elif "barracuda" in server or "barra" in h.get("set-cookie", ""):
            result.update(vendor="Barracuda", detected=True)
        elif "f5" in server or "bigip" in h.get("set-cookie", ""):
            result.update(vendor="F5 BIG-IP", detected=True)
        elif "nginx" in server and r.status_code in (403, 406, 429):
            # Generic WAF blocking via nginx (likely ModSec / NAXSI)
            result.update(vendor="Generic WAF (nginx)", detected=True)
    except Exception as e:
        result["reason"] = f"Probe failed: {type(e).__name__}"
    _WAF_CACHE[host] = result
    return result


def waf_skip_reason(waf_info: dict, scanner_name: str) -> str:
    """Generate a user-friendly skipped_reason when a scanner can't run due to WAF.
    Pass the result of detect_waf() and the scanner's display name.
    """
    if not waf_info.get("detected"):
        return ""
    return (f"{scanner_name} requires direct backend access. "
            f"Target is fronted by {waf_info['vendor']} — aggressive probing will be blocked. "
            f"Whitelist your scanner IP in {waf_info['vendor']} to enable this check.")


def make_req_headers(req: Optional[ScanRequest] = None) -> dict:
    """Merge browser headers with optional auth from a ScanRequest."""
    h = dict(_BROWSER_HEADERS)
    auth = req or _AUTH_CTX.get()
    if auth:
        if getattr(auth, "auth_cookie", None):
            h["Cookie"] = auth.auth_cookie
        if getattr(auth, "auth_bearer", None):
            h["Authorization"] = f"Bearer {auth.auth_bearer}"
    return h


def safe_request(method: str, url: str, *,
                 retries: int = 2,
                 timeout: int = 15,
                 headers: Optional[dict] = None,
                 req: Optional[ScanRequest] = None,
                 verify: bool = False,
                 allow_redirects: bool = True,
                 data=None, json=None, params=None):
    """HTTP request with retry + adaptive timeout + 429-aware backoff.

    Real-world targets behind Cloudflare/AWS WAF throw transient 429s,
    502s, connection resets. This helper retries them transparently and
    extends the timeout 1.5× per attempt so slow targets aren't killed.

    Returns the requests.Response on success, or None after final
    failure (callers do `if r is None: ...`).
    """
    # Always merge auth from req into explicit headers (AUTH-MERGE-V1).
    # Previous behaviour: explicit headers={"Origin":...} silently REPLACED
    # the Cookie/Authorization header set by req — so cors/ssrf/xxe scanners
    # ran unauthenticated even with a captured session.
    if headers is not None:
        h = dict(headers)
        if req is not None:
            if getattr(req, "auth_cookie", None): h.setdefault("Cookie", req.auth_cookie)
            if getattr(req, "auth_bearer", None): h.setdefault("Authorization", f"Bearer {req.auth_bearer}")
        for k, v in _BROWSER_HEADERS.items(): h.setdefault(k, v)
    else:
        h = make_req_headers(req)
    for attempt in range(retries + 1):
        effective_timeout = min(60, int(timeout * (1.5 ** attempt)))
        try:
            kw = dict(timeout=effective_timeout, headers=h, verify=verify,
                      allow_redirects=allow_redirects)
            if data is not None:   kw["data"] = data
            if json is not None:   kw["json"] = json
            if params is not None: kw["params"] = params
            r = _req_lib.request(method.upper(), url, **kw)
            # 429 — honor Retry-After
            if r.status_code == 429 and attempt < retries:
                ra = r.headers.get("Retry-After", "")
                try:
                    wait = float(ra) if ra and ra.isdigit() else 2.0 * (attempt + 1)
                except Exception:
                    wait = 2.0 * (attempt + 1)
                time.sleep(min(wait, 8.0))
                continue
            # 5xx — upstream glitch
            if 500 <= r.status_code < 600 and attempt < retries:
                time.sleep((1.5 ** attempt) + random.random() * 0.5)
                continue
            return r
        except (_req_lib.exceptions.Timeout,
                _req_lib.exceptions.ConnectionError,
                _req_lib.exceptions.ChunkedEncodingError):
            if attempt < retries:
                time.sleep((1.5 ** attempt) + random.random() * 0.4)
                continue
        except Exception:
            return None
    return None


def safe_get(url, **kw):
    _req = kw.get('req')
    if _req is not None:
        _h = dict(kw.get('headers') or {})
        _ac = getattr(_req, 'auth_cookie', None)
        _ab = getattr(_req, 'auth_bearer', None)
        if _ac:
            _ex = _h.get('Cookie', '')
            _h['Cookie'] = (_ex.rstrip('; ') + '; ' + _ac) if _ex else _ac
        if _ab:
            _h['Authorization'] = f'Bearer {_ab}'
        if _h:
            kw['headers'] = _h
    # AUTH INJECTION END

    return safe_request("GET", url, **kw)


def safe_post(url, **kw):
    _req = kw.get('req')
    if _req is not None:
        _h = dict(kw.get('headers') or {})
        _ac = getattr(_req, 'auth_cookie', None)
        _ab = getattr(_req, 'auth_bearer', None)
        if _ac:
            _ex = _h.get('Cookie', '')
            _h['Cookie'] = (_ex.rstrip('; ') + '; ' + _ac) if _ex else _ac
        if _ab:
            _h['Authorization'] = f'Bearer {_ab}'
        if _h:
            kw['headers'] = _h
    # AUTH INJECTION END

    return safe_request("POST", url, **kw)


# ── Trust-First finding shape ───────────────────────────────────────
def wrap_finding(detail: str, severity: str, **kw) -> dict:
    """Stamp a finding with the Trust-First mandatory fields.
    Every finding shipped to the PDF MUST pass through this.

    Required (positional):  detail, severity
    Optional via **kw:
        cvss, cve, cwe, cwe_name, owasp, remediation,
        evidence_marker, tests_performed
    Auto-set:
        confidence:   "CONFIRMED"   (no SUSPECTED tier — see memory
                                     feedback-real-findings-zero-fp)
        verified_at:  ISO timestamp of this stamp
    """
    f = {
        "detail":          detail,
        "severity":        severity,
        "cvss":            kw.get("cvss", "0.0"),
        "cve":             kw.get("cve", "N/A"),
        "cwe":             kw.get("cwe", "N/A"),
        "cwe_name":        kw.get("cwe_name", ""),
        "owasp":           kw.get("owasp", "N/A"),
        "remediation":     kw.get("remediation", ""),
        "confidence":      "CONFIRMED",
        "verified_at":     datetime.datetime.utcnow().isoformat() + "Z",
        "evidence_marker": kw.get("evidence_marker", ""),
        "tests_performed": kw.get("tests_performed", 1),
    }
    # Global advisory cap (Webapp + Vuln + Recon). Scanners that have
    # demonstrated the issue opt out by passing verified_exploit=True.
    if kw.get("verified_exploit"):
        f["verified_exploit"] = True
    else:
        try:
            from tools._framework.severity_policy import is_advisory, _RANK
            blob_name = detail or ""
            blob_evi = f["evidence_marker"] or ""
            cur_rank = _RANK.get(str(severity).upper(), 0)
            if cur_rank > 0 and is_advisory(blob_name, blob_evi):
                f["_original_severity"] = severity
                f["severity"] = "INFO"
                f["_policy"] = "advisory-cap"
        except Exception:
            pass
    return f


def standard_response(*, tool: str, target: str, findings: list,
                      tests_performed: int = 0,
                      tests_summary: str = "",
                      vulnerable: Optional[bool] = None,
                      skipped_reason: Optional[str] = None,
                      raw_data: Optional[dict] = None) -> dict:
    """Standard response shape every tool returns. Keeps the PDF
    generator + frontend consistent across all 100+ tools.

    VL-FOUNDRY Layer 6 (runtime validation): in dev mode, every finding
    is run through finding_schema.validate_ndjson_record before return.
    Bad findings are logged but not blocked — production scans must not
    crash because of a single malformed finding.
    """
    if vulnerable is None:
        vulnerable = any(f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
                         for f in findings)

    # Runtime validation (Gap 6 fix — finding_schema.py is now WIRED, not dead)
    if os.environ.get("VL_VALIDATE_FINDINGS") == "1":
        try:
            from tools._framework.finding_schema import validate_ndjson_record
            for i, f in enumerate(findings):
                ok, errs = validate_ndjson_record(f)
                if not ok:
                    print(f"[VL-VALIDATE] {tool}: finding[{i}] invalid: {errs}",
                          file=sys.stderr)
        except Exception:
            pass  # never crash a scan on the validator path
    resp = {
        "scan_id":         str(uuid.uuid4()),
        "target":          target,
        "tool":            tool,
        "findings":        findings,
        "total":           len(findings),
        "vulnerable":      vulnerable,
        "tests_performed": tests_performed,
        "tests_summary":   tests_summary,
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
    }
    if skipped_reason:
        resp["skipped_reason"] = skipped_reason
        resp["vulnerable"] = False
    if raw_data:
        resp.update(raw_data)
    return resp


def web_url(target: str) -> str:
    """Normalize target string into a valid HTTP URL."""
    if target.startswith(("http://", "https://")):
        return target
    return "http://" + target


def recon_host(target: str) -> str:
    """Extract just the hostname from a target URL or string."""
    from urllib.parse import urlparse
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0]
