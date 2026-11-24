"""Central scope + safety enforcement for CUSTOMER-mode scans (SCOPE-GUARD-V1).

When a scan request carries a `profile_id`, a ScanContext is activated for the
lifetime of that HTTP request (main.py middleware -> `http_gate`). While it is
active, EVERY outbound HTTP request made by any scanner through `requests`,
`httpx` or `aiohttp` (this includes tools/_shared.safe_request/safe_get/
safe_post) is checked here:

  1. allowed time window          -> else blocked_outside_window
  2. scope: out-of-scope wins; must match an in-scope pattern / primary target
     -> else blocked_out_of_scope (a recorded policy outcome, NOT an error)
     Exceptions (never carry credentials, never rate-limit the customer):
       * the configured auth endpoint hosts during a login (session manager)
       * third-party intel services (OOB/CVE feeds always; and for passive
         recon/osint modules any host that is NOT customer-related) when the
         profile's safety.allow_third_party_intel is true (default)
       * safety.extra_allowed_hosts
  3. per-profile token-bucket rate limit (safety.max_rps) for in-scope traffic

Requests WITHOUT a profile_id (LAB mode / legacy) never activate a context, so
every hook below is a pass-through and behaviour is byte-for-byte unchanged.

Also provides `is_destructive_allowed(req)` / `destructive_skip(...)` for
modules, and a central registry of destructive routes that the gate skips
(status SKIPPED with a reason) when the profile disallows destructive tests.
"""
import asyncio
import contextvars
import fnmatch
import ipaddress
import json
import logging
import os
import re
import shlex
import threading
import time
from contextlib import contextmanager
from typing import Optional
from urllib.parse import urlparse

from tools._core import host_header as _hh  # UNDERSCORE-HOST-V4

log = logging.getLogger("vulnuslab.scope_guard")

_SCAN_CTX: contextvars.ContextVar = contextvars.ContextVar("vl_scan_profile_ctx", default=None)
_AUTH_ALLOW: contextvars.ContextVar = contextvars.ContextVar("vl_auth_allow_hosts", default=None)

_INTERNAL_BASE = os.environ.get("VLFORGE_INTERNAL_BASE", "http://127.0.0.1:8000").rstrip("/")

# Module route prefixes whose job is passive third-party intelligence
# gathering (crt.sh, archives, search engines, breach APIs ...).
PASSIVE_PREFIXES = ("/api/osint/", "/api/recon/")

# Always-allowed third-party infrastructure (OOB callback servers, CVE/vuln
# feeds). Never customer assets, so never scope-relevant.
GLOBAL_INTEL_HOSTS = (
    "*.oast.fun", "*.oast.pro", "*.oast.live", "*.oast.site", "*.oast.online",
    "*.oast.me", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online",
    "oast.me", "interact.sh", "*.interact.sh", "*.interactsh.com",
    "services.nvd.nist.gov", "api.osv.dev", "cveawg.mitre.org", "api.first.org",
    "crt.sh", "www.cisa.gov",
)

# ── Destructive registry ───────────────────────────────────────────
# Routes that change server state, flood/DoS, or risk account lockout. With a
# profile whose safety.destructive_allowed is false these are SKIPPED by the
# gate before the module runs. Modules may also call is_destructive_allowed().
DESTRUCTIVE_ROUTES = {
    # credential brute force / spraying (account lockout)
    "/api/password/ftp_brute", "/api/password/hydra_ssh_spray",
    "/api/password/ldap_brute", "/api/password/medusa_smb_spray",
    "/api/password/mysql_brute", "/api/password/ncrack_rdp_spray",
    "/api/password/patator_http_form_brute", "/api/password/postgres_brute",
    "/api/webapp/broken_auth",                 # 10 failed logins back-to-back
    "/api/auth_attacks/mfa_bypass_test",
    # DoS / resource exhaustion / flooding
    "/api/webapp/race_condition",
    "/api/webapp/scan/gzip_bomb_upload",
    "/api/webapp/scan/regex_dos_probe",
    "/api/webapp/scan/saml_response_time_bomb",
    "/api/webapp/scan/websocket_message_size_dos",
    "/api/webapp/scan/cache_stampede_detect",
    "/api/webapp/scan/graphql_batching_abuse",
    # state-changing: uploads, stored payloads, account creation, data writes
    "/api/webapp/scan/file_upload", "/api/webapp/file_upload_bypass",
    "/api/webapp/scan/svg_xss_upload", "/api/webapp/scan/xss_via_filename_upload",
    "/api/webapp/scan/stored_xss",
    "/api/webapp/scan/mass_assignment", "/api/webapp/scan/mass_assignment_patch",
    "/api/webapp/scan/sql_truncation_attack",
    "/api/webapp/password_reset_flaws",        # triggers reset e-mails to real users
    "/api/webapp/scan/csv_injection_export",
    "/api/recon/bucket_perm_audit",            # anonymous PUT into buckets
    # shared-infrastructure poisoning (affects real users of the site)
    "/api/webapp/cache_poisoning", "/api/webapp/http_smuggling",
    "/api/webapp/scan/http2_request_smuggling", "/api/webapp/scan/h2c_smuggling",
}
DESTRUCTIVE_PREFIXES = (
    "/api/red_team/", "/api/post_exploit/", "/api/post/",
    # active exploitation: real payload delivery / shells / privilege changes
    "/api/exploit/", "/api/system_exploit/", "/api/metasploit/", "/api/privesc/",
)


def is_destructive_route(path: str) -> bool:
    p = (path or "").rstrip("/")
    return p in DESTRUCTIVE_ROUTES or any(p.startswith(x) for x in DESTRUCTIVE_PREFIXES)


# ── Scan context ───────────────────────────────────────────────────
class ScanContext:
    __slots__ = ("rt", "user_id", "path", "passive", "lock", "stats", "samples",
                 "auth_role", "auth_mode", "approved_hosts", "approved_nets", "_approved_ips")

    def __init__(self, rt, user_id: str, path: str = "", auth_role: Optional[str] = None,
                 auth_mode: Optional[str] = None):
        self.rt = rt
        self.auth_role = auth_role
        self.auth_mode = auth_mode
        self.user_id = user_id
        self.path = path or ""
        self.passive = any(self.path.startswith(p) for p in PASSIVE_PREFIXES)
        self.lock = threading.Lock()
        self.stats = {"in_scope": 0, "third_party_intel": 0, "auth_provider": 0,
                      "blocked_out_of_scope": 0, "blocked_outside_window": 0,
                      "blocked_rate_limit": 0, "rate_limit_wait_sec": 0.0,
                      "subprocess_in_scope": 0, "subprocess_blocked": 0}
        self.samples: list = []
        # Hosts the gate already verified in scope (the request's primary
        # target). Subprocess tools may address them by a resolved IP.
        self.approved_hosts: set = set()
        self.approved_nets: list = []
        self._approved_ips = None

    @property
    def profile_id(self) -> str:
        return self.rt.id

    def record(self, category: str, url: str = "", reason: str = "", wait: float = 0.0):
        with self.lock:
            self.stats[category] = self.stats.get(category, 0) + 1
            if wait:
                self.stats["rate_limit_wait_sec"] = round(self.stats["rate_limit_wait_sec"] + wait, 2)
            if category.startswith("blocked") and len(self.samples) < 10:
                self.samples.append({"url": url[:300], "category": category, "reason": reason[:200]})

    def approve(self, target: str) -> None:
        """Mark a gate-verified scan target as approved for subprocess tools."""
        t = (target or "").strip()
        if "/" in t and "://" not in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                net = None
            if net is not None:
                with self.lock:
                    self.approved_nets.append(net)
                return
        h = _host_of(t) if t else ""
        if h:
            with self.lock:
                self.approved_hosts.add(h.strip("[]"))
                self._approved_ips = None

    def approved_ips(self) -> set:
        with self.lock:
            if self._approved_ips is not None:
                return self._approved_ips
            hosts = set(self.approved_hosts)
        from tools._core.target_profile import _ip_of, _resolve
        ips = set()
        for h in hosts:
            if _ip_of(h) is not None:
                ips.add(str(_ip_of(h)))
            else:
                ips.update(_resolve(h))
        with self.lock:
            self._approved_ips = ips
        return ips

    def bump(self, key: str, n: int = 1) -> None:
        with self.lock:
            self.stats[key] = self.stats.get(key, 0) + n

    @property
    def blocked(self) -> int:
        return sum(v for k, v in self.stats.items() if k.startswith("blocked"))

    def summary(self) -> dict:
        with self.lock:
            return {"profile_id": self.rt.id, **dict(self.stats),
                    "blocked_total": self.blocked, "blocked_samples": list(self.samples)}


def current() -> Optional[ScanContext]:
    return _SCAN_CTX.get()


def activate(ctx: Optional[ScanContext]):
    """Set the context; returns a token for deactivate()."""
    return _SCAN_CTX.set(ctx)


def deactivate(token) -> None:
    try:
        _SCAN_CTX.reset(token)
    except Exception:
        _SCAN_CTX.set(None)


@contextmanager
def scan_context(ctx: Optional[ScanContext]):
    tok = activate(ctx)
    try:
        yield ctx
    finally:
        deactivate(tok)


@contextmanager
def auth_endpoint_allowance(hosts):
    """Allow the session manager's configured auth endpoints (login_url /
    token_url hosts) for the duration of a login, even if out of scope."""
    prev = _AUTH_ALLOW.get()
    tok = _AUTH_ALLOW.set(frozenset(set(prev or ()) | {h.lower() for h in (hosts or ())}))
    try:
        yield
    finally:
        _AUTH_ALLOW.reset(tok)


# ── Rate limiting (token bucket per profile) ───────────────────────
_WORKERS = max(1, int(os.environ.get("WORKERS", "2") or 2))
_MAX_RATE_WAIT = float(os.environ.get("VL_PROFILE_MAX_RATE_WAIT", "90"))


class _Bucket:
    __slots__ = ("rate", "cap", "tokens", "ts", "lock")

    def __init__(self, rate: float):
        self.rate = rate
        self.cap = max(1.0, rate)
        self.tokens = self.cap
        self.ts = time.monotonic()
        self.lock = threading.Lock()

    def reserve(self) -> Optional[float]:
        """Reserve one token. Returns seconds to wait, or None if the backlog
        exceeds _MAX_RATE_WAIT (caller should give up on that request)."""
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
            self.ts = now
            wait = 0.0 if self.tokens >= 1 else (1 - self.tokens) / self.rate
            if wait > _MAX_RATE_WAIT:
                return None
            self.tokens -= 1
            return wait


_BUCKETS: dict = {}
_BUCKETS_LOCK = threading.Lock()


def _bucket_for(rt) -> _Bucket:
    # The per-profile budget is split across uvicorn workers (fan-out lands on
    # any worker), so the cluster-wide rate never exceeds max_rps.
    rate = max(0.05, float(rt.safety.get("max_rps") or 10.0) / _WORKERS)
    with _BUCKETS_LOCK:
        b = _BUCKETS.get(rt.id)
        if b is None or abs(b.rate - rate) > 1e-9:
            b = _BUCKETS[rt.id] = _Bucket(rate)
        return b


# ── Decision ───────────────────────────────────────────────────────
def _host_of(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except Exception:
        return ""


def _host_in(host: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns or ())


def classify(url: str, ctx: Optional[ScanContext] = None) -> tuple[bool, str, str]:
    """(allowed, category, reason) for one outbound URL. Pure decision, no
    side effects. With no active context everything is allowed."""
    ctx = ctx or current()
    if ctx is None:
        return True, "", ""
    if _is_internal(url):
        return True, "internal", ""
    host = _host_of(url)
    allow = _AUTH_ALLOW.get()
    if allow and host in allow:
        return True, "auth_provider", "configured auth endpoint"
    from tools._core.target_profile import within_time_window
    safety = ctx.rt.safety
    if not within_time_window(safety.get("time_window")):
        return False, "blocked_outside_window", "outside the profile's allowed testing window"
    ok, why = ctx.rt.scope.decide(url)
    if ok:
        return True, "in_scope", why
    if "out-of-scope pattern" not in why:
        if _host_in(host, safety.get("extra_allowed_hosts")):
            return True, "third_party_intel", "safety.extra_allowed_hosts"
        if safety.get("allow_third_party_intel", True) and not ctx.rt.scope.is_customer_related(url):
            if _host_in(host, GLOBAL_INTEL_HOSTS):
                return True, "third_party_intel", "global intel/OOB service"
            if ctx.passive:
                return True, "third_party_intel", "passive module, non-customer host"
    return False, "blocked_out_of_scope", why


def precheck(url: str) -> bool:
    """Cheap pre-flight used by safe_request so a blocked URL returns None at
    once (instead of burning retries). Records blocks; allowed requests are
    recorded/rate-limited by the transport hook."""
    ctx = current()
    if ctx is None:
        return True
    ok, cat, why = classify(url, ctx)
    if not ok:
        ctx.record(cat, url, why)
        log.info("scope: %s %s (%s) profile=%s", cat, url[:200], why, ctx.profile_id)
    return ok


def _admit(url: str) -> tuple[bool, str, str, float]:
    """Classify + record + reserve rate. Returns (ok, category, reason, wait)."""
    ctx = current()
    ok, cat, why = classify(url, ctx)
    if ctx is None or cat == "internal":
        return True, cat, why, 0.0
    if not ok:
        ctx.record(cat, url, why)
        return False, cat, why, 0.0
    wait = 0.0
    if cat == "in_scope":
        w = _bucket_for(ctx.rt).reserve()
        if w is None:
            ctx.record("blocked_rate_limit", url, "rate-limit backlog too long")
            return False, "blocked_rate_limit", "per-profile rate limit backlog exceeded", 0.0
        wait = w
    ctx.record(cat, url, why, wait=wait)
    return True, cat, why, wait


class ScopeBlockedMixin:
    category = "blocked_out_of_scope"


def _blocked_msg(url, cat, why):
    return f"VulnusLab {cat}: {url[:200]} ({why})"


def guard_sync(url: str, exc_cls=None) -> None:
    ok, cat, why, wait = _admit(url)
    if not ok:
        cls = exc_cls or _RequestsBlocked
        e = cls(_blocked_msg(url, cat, why))
        try:
            e.category = cat
        except Exception:
            pass
        raise e
    if wait > 0:
        time.sleep(wait)


async def guard_async(url: str, exc_cls) -> None:
    ok, cat, why, wait = _admit(url)
    if not ok:
        e = exc_cls(_blocked_msg(url, cat, why))
        try:
            e.category = cat
        except Exception:
            pass
        raise e
    if wait > 0:
        await asyncio.sleep(wait)


# ── Transport hooks (requests / httpx / aiohttp) ───────────────────
try:
    import requests as _requests

    class _RequestsBlocked(ScopeBlockedMixin, _requests.exceptions.ConnectionError):
        pass
except Exception:  # pragma: no cover
    _requests = None

    class _RequestsBlocked(ScopeBlockedMixin, ConnectionError):
        pass

_installed = False
_install_lock = threading.Lock()


def _is_internal(url: str) -> bool:
    return url == _INTERNAL_BASE or url.startswith(_INTERNAL_BASE + "/")


def _inject_profile_json(raw) -> Optional[bytes]:
    """Backstop for nested internal fan-out (an aggregator scanner calling
    other scanners over localhost): a JSON body that lacks profile_id gets the
    active context's profile_id + auth_role, so the child request is gated and
    scope-enforced too instead of silently running in LAB mode. Returns new
    bytes, or None when nothing changes."""
    ctx = current()
    if ctx is None or not raw:
        return None
    try:
        data = json.loads(raw if isinstance(raw, (bytes, str)) else bytes(raw))
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("profile_id"):
        return None
    data["profile_id"] = ctx.rt.id
    if ctx.auth_role and not data.get("auth_role"):
        data["auth_role"] = ctx.auth_role
    return json.dumps(data).encode()


def install_transport_guards() -> None:
    """Idempotently hook the HTTP client libraries + ThreadPoolExecutor.
    Every hook is a pass-through when no ScanContext is active."""
    global _installed
    with _install_lock:
        if _installed:
            return
        _installed = True

    if _requests is not None:
        _orig_send = _requests.Session.send

        def _vl_send(self, request, **kw):
            # UNDERSCORE-HOST-V4 — every mode, every hop (see host_header.py).
            try:
                _ru = _hh.restore_url(request.url or "")
                if _ru:  # redirect hop to a cleaned lab name -> real name
                    request.url = _ru
                    request.headers.pop("Host", None)
                _nh = _hh.should_replace(request.url or "", request.headers.get("Host"))
                if _nh:
                    request.headers["Host"] = _nh
            except Exception:
                pass
            if _SCAN_CTX.get() is not None:
                url = request.url or ""
                if _is_internal(url):
                    nb = _inject_profile_json(request.body) if request.body else None
                    if nb is not None:
                        request.body = nb
                        request.headers["Content-Length"] = str(len(nb))
                else:
                    guard_sync(url, _RequestsBlocked)
            return _orig_send(self, request, **kw)
        _requests.Session.send = _vl_send

    try:
        import httpx

        class _HttpxBlocked(ScopeBlockedMixin, httpx.ConnectError):
            def __init__(self, msg):
                super().__init__(msg)

        _o_csend = httpx.Client.send
        _o_asend = httpx.AsyncClient.send

        def _rebuild(request):
            try:
                nb = _inject_profile_json(request.content)
            except Exception:
                nb = None
            if nb is None:
                return request
            hdrs = [(k, v) for k, v in request.headers.items() if k.lower() != "content-length"]
            return httpx.Request(request.method, request.url, headers=hdrs, content=nb,
                                 extensions=request.extensions)

        def _fix_httpx_host(request):
            try:
                _ru = _hh.restore_url(str(request.url))
                if _ru:
                    request.url = httpx.URL(_ru)
                    if "Host" in request.headers:
                        del request.headers["Host"]
                _nh = _hh.should_replace(str(request.url), request.headers.get("Host"))
                if _nh:
                    request.headers["Host"] = _nh
            except Exception:
                pass

        def _vl_csend(self, request, *a, **kw):
            _fix_httpx_host(request)
            if _SCAN_CTX.get() is not None:
                if _is_internal(str(request.url)):
                    request = _rebuild(request)
                else:
                    guard_sync(str(request.url), _HttpxBlocked)
            return _o_csend(self, request, *a, **kw)

        async def _vl_asend(self, request, *a, **kw):
            _fix_httpx_host(request)
            if _SCAN_CTX.get() is not None:
                if _is_internal(str(request.url)):
                    request = _rebuild(request)
                else:
                    await guard_async(str(request.url), _HttpxBlocked)
            return await _o_asend(self, request, *a, **kw)
        httpx.Client.send = _vl_csend
        httpx.AsyncClient.send = _vl_asend
        # UNDERSCORE-HOST-V4 — httpx sends redirect hops via the internal
        # _send_single_request, not send(); hook it so a Tomcat-style
        # absolute redirect to the cleaned name is restored too.
        if hasattr(httpx.Client, "_send_single_request"):
            _o_cssr = httpx.Client._send_single_request

            def _vl_cssr(self, request, *a, **kw):
                _fix_httpx_host(request)
                return _o_cssr(self, request, *a, **kw)
            httpx.Client._send_single_request = _vl_cssr
        if hasattr(httpx.AsyncClient, "_send_single_request"):
            _o_assr = httpx.AsyncClient._send_single_request

            async def _vl_assr(self, request, *a, **kw):
                _fix_httpx_host(request)
                return await _o_assr(self, request, *a, **kw)
            httpx.AsyncClient._send_single_request = _vl_assr
    except Exception as e:  # httpx absent / API drift — fail open for LAB
        log.debug("httpx guard not installed: %s", e)

    try:
        import aiohttp

        class _AiohttpBlocked(ScopeBlockedMixin, aiohttp.ClientConnectionError):
            pass

        _o_req = aiohttp.ClientSession._request

        async def _vl_request(self, method, str_or_url, *a, **kw):
            try:
                _hdrs = kw.get("headers")
                _cur = None
                if _hdrs:
                    for _k, _v in dict(_hdrs).items():
                        if str(_k).lower() == "host":
                            _cur = _v
                _ru = _hh.restore_url(str(str_or_url))
                if _ru:
                    str_or_url, _cur = _ru, None
                _nh = _hh.should_replace(str(str_or_url), _cur)
                if _nh:
                    _new = {k: v for k, v in dict(_hdrs or {}).items() if str(k).lower() != "host"}
                    _new["Host"] = _nh
                    kw["headers"] = _new
            except Exception:
                pass
            if _SCAN_CTX.get() is not None:
                await guard_async(str(str_or_url), _AiohttpBlocked)
            return await _o_req(self, method, str_or_url, *a, **kw)
        aiohttp.ClientSession._request = _vl_request
        # UNDERSCORE-HOST-V4 — aiohttp follows redirects inside _request with
        # no per-hop hook, so resolve cleaned lab names (labwebgoat) to the
        # real container name at DNS time instead.
        try:
            import aiohttp.resolver as _ar
            for _cls_name in ("ThreadedResolver", "AsyncResolver"):
                _cls = getattr(_ar, _cls_name, None)
                if _cls is None or getattr(_cls, "_vl_host_patched", False):
                    continue
                _o_resolve = _cls.resolve

                def _mk(_orig):
                    async def _vl_resolve(self, host, *a, **kw):
                        _real = _hh._REVERSE.get(str(host).lower()) if "_" not in str(host) else None
                        return await _orig(self, _real or host, *a, **kw)
                    return _vl_resolve
                _cls.resolve = _mk(_o_resolve)
                _cls._vl_host_patched = True
        except Exception as e:
            log.debug("aiohttp resolver patch not installed: %s", e)
    except Exception as e:
        log.debug("aiohttp guard not installed: %s", e)

    # Context propagation into worker threads: scanners fan probes out over
    # their own ThreadPoolExecutors, which do NOT inherit contextvars. Without
    # this, a request made from a worker thread would escape the scope guard.
    # Only engaged while a ScanContext is active (LAB mode untouched).
    import concurrent.futures as _cf
    _o_submit = _cf.ThreadPoolExecutor.submit

    def _vl_submit(self, fn, /, *args, **kwargs):
        if _SCAN_CTX.get() is not None:
            ctx = contextvars.copy_context()
            return _o_submit(self, ctx.run, fn, *args, **kwargs)
        return _o_submit(self, fn, *args, **kwargs)
    _cf.ThreadPoolExecutor.submit = _vl_submit

    # SCOPE-GUARD-SUBPROC-V1 backstop: every child process (subprocess.run /
    # Popen / check_output and asyncio.create_subprocess_exec, which all end
    # in Popen._execute_child) has its argv scope-checked before it starts.
    try:
        import subprocess as _sp
        _o_exec_child = _sp.Popen._execute_child

        def _vl_execute_child(self, args, *a, **kw):
            if _SCAN_CTX.get() is not None:
                guard_subprocess_argv(args)
            return _o_exec_child(self, args, *a, **kw)
        _sp.Popen._execute_child = _vl_execute_child
    except Exception as e:  # pragma: no cover
        log.warning("subprocess scope guard not installed: %s", e)
    log.info("SCOPE-GUARD-V1 transport guards installed")


# ── Destructive policy helpers for modules ─────────────────────────
def is_destructive_allowed(req=None) -> bool:
    """True in LAB mode (no profile). In CUSTOMER mode, the profile's
    safety.destructive_allowed (default False). Fails closed if a request
    names a profile but no context is active."""
    ctx = current()
    if ctx is not None:
        return bool(ctx.rt.safety.get("destructive_allowed", False))
    if getattr(req, "profile_id", None):
        return False
    return True


def skip_payload(tool: str, target: str, reason: str, category: str) -> dict:
    """Standard SKIPPED result — never reads as a clean pass."""
    import datetime
    import uuid
    return {
        "scan_id": str(uuid.uuid4()), "tool": tool, "target": target,
        "status": "SKIPPED", "_skipped": True, "skipped": True, "skip_category": category,
        "skipped_reason": reason, "findings": [], "total": 0,
        "vulnerable": False, "severity": "INFO", "tests_performed": 0,
        "tests_summary": f"SKIPPED ({category}): {reason}",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }


def destructive_skip(req, tool: str) -> Optional[dict]:
    """Return a SKIPPED payload if destructive tests are not allowed, else None."""
    if is_destructive_allowed(req):
        return None
    return skip_payload(tool, getattr(req, "target", "") or "",
                        "Destructive / state-changing test disabled by the target "
                        "profile (safety.destructive_allowed=false).",
                        "destructive_not_allowed")


# ── Subprocess scope enforcement (SCOPE-GUARD-SUBPROC-V1) ──────────
# The transport hooks above only see HTTP made from Python. Scanners that
# shell out (nmap, nuclei, sqlmap, nikto, hydra, msfconsole, impacket ...) do
# their own networking, so the gate's primary-target check was the only thing
# between a request and an out-of-scope host (msf RHOSTS option, patator form
# action URL, a resolved IP, a CIDR ...). Two layers, both pass-through when
# no ScanContext is active (LAB mode / lab_* targets are untouched):
#
#   1. Explicit:  subprocess_scope_block(targets, tool) / subprocess_scope_skip()
#      called by runners/tools right before they launch, with the exact
#      host/URL/IP/CIDR handed to the binary. Strict: the target must be in
#      scope (same ScopeRules + classify() used for HTTP traffic).
#   2. Backstop:  subprocess.Popen._execute_child is hooked (asyncio's
#      create_subprocess_exec goes through Popen as well). Network-looking
#      argv tokens (URLs, IPs, CIDRs, IP ranges, user@host, host names) are
#      checked before the process is created; a violation raises
#      ScopeBlockedSubprocess and the process never starts.
#
# Every block is recorded on the ScanContext (category blocked_out_of_scope +
# a subprocess_blocked counter), so annotate_response() turns a tool whose
# external scanner never ran into status SKIPPED - never a silent clean.

class ScopeBlockedSubprocess(ScopeBlockedMixin, PermissionError):
    """Raised by the Popen backstop instead of launching an out-of-scope
    subprocess. PermissionError so generic `except Exception` handlers keep
    working; deliberately not FileNotFoundError (that reads as 'not installed')."""


# Binaries whose arguments are lookup keys, not hosts they connect to.
QUERY_ONLY_BINARIES = frozenset({"whois", "jwhois", "dig", "host", "nslookup", "drill", "delv"})

# Bare-hostname-looking values of these flags are names/files (AD domain,
# user, wordlist, template, output file ...), not targets. URLs / IPs after
# them are still checked.
_NON_TARGET_FLAGS = frozenset({
    "-d", "--domain", "-u", "--user", "--username", "-U", "-p", "--password", "-P",
    "-o", "-oX", "-oN", "-oG", "-oA", "-oJ", "--output", "--output-dir", "-w",
    "--wordlist", "-t", "-templates", "--templates", "-l", "-L", "-c", "--config",
    "-H", "--header", "--script", "--script-args", "-x", "-f", "--file", "-b",
})
_FILE_EXTS = frozenset({
    "json", "jsonl", "xml", "txt", "csv", "yaml", "yml", "nse", "py", "sh", "log", "html",
    "htm", "conf", "cfg", "ini", "lst", "dic", "gz", "zip", "tar", "tgz", "pcap", "pcapng",
    "cap", "hccapx", "hc22000", "apk", "ipa", "bin", "img", "so", "jar", "js", "rb", "pl",
    "out", "db", "sqlite", "key", "pem", "crt", "der", "rc", "md", "lock", "toml", "sarif",
})
_HOST_RE = re.compile(
    r"^(?=.{4,253}(?::\d{1,5})?$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z]{2,63}\.?(?::\d{1,5})?$", re.I)
_URL_RE = re.compile(r"([a-z][a-z0-9+.\-]{1,15})://([^\s'\"<>;,|]+)", re.I)
_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_WEB_SCHEMES = ("http", "https", "ws", "wss")


def _ip_literal(s: str):
    try:
        return ipaddress.ip_address((s or "").strip("[]"))
    except ValueError:
        return None


def _parse_target_token(tok: str) -> list:
    """Network targets in ONE token -> [(kind, check, host)].
    kind: url | svc | ip | cidr | host; `check` is what the scope rules see."""
    t = (tok or "").strip().strip("'\"").rstrip(";,)")
    if not t or len(t) > 2048:
        return []
    m = _URL_RE.search(t)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        url = f"{scheme}://{rest}"
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower()
            port = p.port
        except ValueError:
            return []
        if not host:
            return []
        if scheme in _WEB_SCHEMES:
            return [("url", url, host)]
        hp = f"[{host}]" if ":" in host else host
        return [("svc", f"{hp}:{port}" if port else hp, host)]
    if "@" in t and not t.startswith("@"):
        t = t.rsplit("@", 1)[1]                 # user@host, DOMAIN/user@host
    t = t.lstrip("@").rstrip(".")
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return []
        if net.num_addresses > 1:
            return [("cidr", str(net), str(net.network_address))]
        return [("ip", str(net.network_address), str(net.network_address))]
    rm = _RANGE_RE.match(t)
    if rm:                                       # nmap-style 10.0.0.1-50
        ends = (f"{rm.group(1)}{rm.group(2)}", f"{rm.group(1)}{rm.group(3)}")
        return [("ip", x, x) for x in ends if _ip_literal(x) is not None]
    ip = _ip_literal(t)
    if ip is not None:
        return [("ip", str(ip), str(ip))]
    if t.startswith("[") and "]:" in t:          # [v6]:port
        h = t[1:t.index("]")]
        if _ip_literal(h) is not None:
            return [("ip", t, h)]
    if t.count(":") == 1:
        h, _, prt = t.partition(":")
        if prt.isdigit() and _ip_literal(h) is not None:
            return [("ip", t, h)]
    if _HOST_RE.match(t):
        return [("host", t, t.split(":", 1)[0].rstrip(".").lower())]
    return []


def _argv_list(args) -> list:
    if isinstance(args, (str, bytes)):
        a = os.fsdecode(args)
        try:
            return shlex.split(a)
        except ValueError:
            return a.split()
    out = []
    for a in args or ():
        try:
            out.append(os.fsdecode(a) if isinstance(a, (bytes, os.PathLike)) else str(a))
        except Exception:
            out.append(str(a))
    return out


def _is_local_ip(h: str) -> bool:
    ip = _ip_literal(h)
    return ip is not None and (ip.is_loopback or ip.is_unspecified)


def argv_targets(args) -> list:
    """Network targets in an argv -> [(kind, check, host, lenient)].
    `lenient` marks bare host names, which may just be file/config names.
    Loopback / unspecified IPs (bind addresses, local DB) are not targets."""
    argv = _argv_list(args)
    if not argv:
        return []
    exe = os.path.basename(argv[0]).lower()
    if exe in QUERY_ONLY_BINARIES:
        return []
    found, prev = [], ""

    def _add(k, chk, h, lenient):
        if k in ("ip", "svc", "url") and _is_local_ip(h):
            return
        found.append((k, chk, h, lenient))

    for a in argv[1:]:
        if any(c.isspace() for c in a):
            # Embedded script / option string (msfconsole -x, sh -c ...):
            # only unambiguous network tokens (URL / IP / CIDR).
            for piece in re.split(r"[\s;,'\"()\[\]{}]+", a):
                for k, chk, h in _parse_target_token(piece):
                    if k != "host":
                        _add(k, chk, h, False)
            prev = ""
            continue
        val, flag = a, prev
        if a.startswith("-"):
            if "=" not in a:
                prev = a
                continue
            flag, val = a.split("=", 1)
        elif "=" in a and "://" not in a.split("=", 1)[0]:
            val = a.split("=", 1)[1]             # KEY=value (patator url=..., RHOSTS=...)
        prev = ""
        pieces = [val] if "://" in val else val.split(",")
        for piece in pieces:
            for k, chk, h in _parse_target_token(piece):
                if k == "host":
                    ext = h.rsplit(".", 1)[-1]
                    if flag in _NON_TARGET_FLAGS or ext in _FILE_EXTS or os.path.exists(piece):
                        continue
                    _add(k, chk, h, True)
                else:
                    _add(k, chk, h, False)
    return found


def _decide_subprocess_target(ctx: "ScanContext", kind: str, check: str, host: str,
                              lenient: bool) -> tuple:
    """(allowed, category, reason) for one subprocess target."""
    from tools._core.target_profile import _parse_url, within_time_window
    rt = ctx.rt
    if not within_time_window(rt.safety.get("time_window")):
        return False, "blocked_outside_window", "outside the profile's allowed testing window"
    if kind == "cidr":
        net = ipaddress.ip_network(check, strict=False)
        if any(net.version == n.version and net.subnet_of(n) for n in ctx.approved_nets):
            for p in rt.scope.out:          # out-of-scope still wins inside an approved range
                if p.kind == "cidr" and net.version == p.net.version and net.overlaps(p.net):
                    return False, "blocked_out_of_scope", f"range overlaps out-of-scope {p.raw!r}"
            return True, "in_scope", "inside the approved scan range"
        ok, why = rt.scope.target_in_scope(check)
        return ok, ("in_scope" if ok else "blocked_out_of_scope"), why
    u = _parse_url(check)
    if u is None:
        return False, "blocked_out_of_scope", "unparseable target"
    customer = rt.scope.is_customer_related(check)
    # Out-of-scope patterns always win, even over the approved primary target.
    resolve = customer or not lenient
    for p in rt.scope.out:
        if p.matches(u, resolve=resolve, any_ip=True):
            return False, "blocked_out_of_scope", f"matches out-of-scope pattern {p.raw!r}"
    h = host.strip("[]").lower()
    if h in ctx.approved_hosts:
        return True, "in_scope", "approved scan target"
    ip = _ip_literal(h)
    if ip is not None:
        if any(ip.version == n.version and ip in n for n in ctx.approved_nets):
            return True, "in_scope", "inside the approved scan range"
        if str(ip) in ctx.approved_ips():
            return True, "in_scope", "address of the approved scan target"
    ok, cat, why = classify(check, ctx)
    if ok:
        return True, cat, why
    if lenient and not customer and "out-of-scope pattern" not in why:
        return True, "ignored", "bare name unrelated to the customer (not treated as a target)"
    return False, cat, why


def _check_subprocess_targets(ctx, targets: list, tool: str) -> tuple:
    """targets: [(kind, check, host, lenient)] -> (ok, category, reason, target).
    Records the outcome on ctx."""
    checked = 0
    for kind, check, host, lenient in targets:
        ok, cat, why = _decide_subprocess_target(ctx, kind, check, host, lenient)
        if not ok:
            ctx.record(cat, f"subprocess:{tool} {check}", why)
            ctx.bump("subprocess_blocked")
            log.info("scope: subprocess %s target %s blocked (%s: %s) profile=%s",
                     tool, check[:200], cat, why, ctx.profile_id)
            return False, cat, why, check
        if cat != "ignored":
            checked += 1
    if checked:
        ctx.bump("subprocess_in_scope")
    return True, "", "", ""


def _explicit_targets(targets) -> list:
    if targets is None or isinstance(targets, (str, bytes)):
        targets = [targets] if targets else []
    out = []
    for t in targets:
        t = (os.fsdecode(t) if isinstance(t, bytes) else str(t or "")).strip()
        if not t:
            continue
        parsed = [] if any(c.isspace() for c in t) else _parse_target_token(t)
        if not parsed:
            pieces = [x for x in re.split(r"[\s,]+", t) if x]
            if len(pieces) > 1:                 # "10.0.0.1 10.0.0.2" / "a.com,b.com"
                out.extend(_explicit_targets(pieces))
                continue
            # Anything else (single-label "dc01", "lab_dvwa" ...) is checked
            # as a host and must be covered by the scope.
            parsed = [("host", t, _host_of(t) or t.lower())]
        out.extend((k, c, h, False) for k, c, h in parsed)
    return out


def subprocess_scope_block(targets, tool: str = "subprocess") -> Optional[str]:
    """Check the host(s)/URL(s)/IP(s)/CIDR(s) a tool is ABOUT to hand to an
    external binary against the active profile's scope. Returns None when
    allowed (always in LAB mode), else a human-readable SKIPPED reason. Blocks
    are recorded on the scan context. Call it right before launching."""
    ctx = current()
    if ctx is None:
        return None
    ok, cat, why, tgt = _check_subprocess_targets(ctx, _explicit_targets(targets), tool)
    if ok:
        return None
    label = ("outside the profile's allowed testing window" if cat == "blocked_outside_window"
             else "out of scope for this target profile")
    return (f"{tool}: not launched - target {tgt[:200]} is {label} ({why}). "
            f"Nothing was tested against it.")


def subprocess_scope_skip(tool: str, targets, report_target: Optional[str] = None) -> Optional[dict]:
    """Standard SKIPPED payload when a subprocess target is out of scope, else None."""
    reason = subprocess_scope_block(targets, tool)
    if reason is None:
        return None
    if isinstance(targets, (list, tuple)):
        first = str(targets[0]) if targets else ""
    else:
        first = str(targets or "")
    cat = "outside_window" if "testing window" in reason else "out_of_scope"
    return skip_payload(tool, report_target or first, reason, cat)


_KUBE_SERVER_RE = re.compile(r"^\s*server:\s*['\"]?([^\s'\"#]+)", re.M)


def kubeconfig_servers(kubeconfig_text: str) -> list:
    """API-server URLs named in a kubeconfig (kubectl / kube-bench take the
    target from the KUBECONFIG file, so it never appears in argv)."""
    return _KUBE_SERVER_RE.findall(kubeconfig_text or "")[:20]


def guard_subprocess_argv(args) -> None:
    """Backstop for every subprocess launched while a ScanContext is active.
    Raises ScopeBlockedSubprocess before the process is created."""
    ctx = current()
    if ctx is None:
        return
    try:
        targets = argv_targets(args)
        argv0 = _argv_list(args)[:1]
    except Exception as e:     # never break a launch on a parser bug
        log.debug("subprocess argv parse failed: %s", e)
        return
    if not targets:
        return
    tool = os.path.basename(argv0[0]) if argv0 else "subprocess"
    ok, cat, why, tgt = _check_subprocess_targets(ctx, targets, tool)
    if not ok:
        e = ScopeBlockedSubprocess(
            f"VulnusLab {cat}: {tool} not launched - target {tgt[:200]} is out of scope "
            f"for this target profile ({why})")
        e.category = cat
        raise e


# ── HTTP gate (called from main.py middleware) ─────────────────────
def _tool_name(path: str) -> str:
    return (path or "").rstrip("/").rsplit("/", 1)[-1] or "scan"


def _user_from_request(request) -> Optional[str]:
    # SESSION-COOKIE-V1: Bearer header, else the HttpOnly session cookie
    # (main.py's cookie middleware normally converts a CSRF-checked cookie
    # into a Bearer header before this runs).
    from tools.auth._session_cookie import SESSION_COOKIE, real_bearer
    raw = real_bearer(request.headers.get("authorization") or "")
    if not raw:
        try:
            raw = request.cookies.get(SESSION_COOKIE) or ""
        except Exception:
            raw = ""
    if not raw:
        return None
    try:
        from jose import jwt as _jwt
        payload = _jwt.decode(raw, os.getenv("JWT_SECRET", ""), algorithms=["HS256"])
        sub = payload.get("sub")
        return str(sub) if sub else None
    except Exception:
        return None


def is_orchestrator_path(path: str) -> bool:
    return "/run_all" in (path or "")


async def http_gate(request, path: str, payload):
    """Pre-dispatch gate for a POST /api/* JSON request.

    Returns (early_response, ctx, new_body):
      * early_response — a Response to send instead of running the route
        (401/403/404, or a 200 SKIPPED payload for internal fan-out), or None
      * ctx            — ScanContext to activate for the route, or None (LAB)
      * new_body       — re-serialised body bytes when auth was injected
    """
    from starlette.responses import JSONResponse
    if not isinstance(payload, dict) or not payload.get("profile_id"):
        return None, None, None
    pid = str(payload.get("profile_id"))[:64]
    user_id = _user_from_request(request)
    if not user_id:
        return JSONResponse(status_code=401, content={"detail": "Authentication required for profile scans"}), None, None
    from tools._core.target_profile import get_runtime_profile, within_time_window
    try:
        rt = await asyncio.to_thread(get_runtime_profile, pid, user_id)
    except Exception as e:
        log.warning("profile load failed: %s", type(e).__name__)
        return JSONResponse(status_code=503, content={"detail": "Target profile could not be loaded"}), None, None
    if rt is None:
        return JSONResponse(status_code=404, content={"detail": "Target profile not found"}), None, None

    from tools._shared import is_internal_fanout
    fanout = is_internal_fanout(request)
    target = str(payload.get("target") or payload.get("host") or payload.get("url") or "")
    tool = _tool_name(path)

    def _refuse(reason: str, category: str):
        if fanout:
            return JSONResponse(status_code=200, content=skip_payload(tool, target, reason, category))
        return JSONResponse(status_code=403, content={"detail": reason, "skip_category": category})

    if not within_time_window(rt.safety.get("time_window")):
        return _refuse("Outside the target profile's allowed testing window.", "outside_window"), None, None
    if target:
        ok, why = rt.scope.target_in_scope(target)
        if not ok:
            return _refuse(f"Target {target[:200]} is out of scope for this profile: {why}.",
                           "out_of_scope"), None, None
    if is_destructive_route(path) and not rt.safety.get("destructive_allowed", False):
        return _refuse("Destructive / state-changing test disabled by the target profile "
                       "(safety.destructive_allowed=false).", "destructive_not_allowed"), None, None

    role = str(payload.get("auth_role"))[:64] if payload.get("auth_role") else None
    if role and rt.role(role) is None:
        return JSONResponse(status_code=400, content={"detail": f"Profile has no auth role {role!r}"}), None, None
    ctx = ScanContext(rt, user_id, path, auth_role=role,
                      auth_mode=payload.get("auth_mode") if payload.get("auth_mode") in
                      ("authenticated", "unauthenticated") else None)
    if target:
        ctx.approve(target)      # passed target_in_scope above
    new_body = None
    # Per-tool auth (re)injection: every scanner request carrying a profile_id
    # gets the CURRENT session for its role, so an expired session is re-logged
    # in centrally mid-scan. Orchestrator run_all calls resolve auth themselves.
    if rt.cfg.get("auth_configs") and not is_orchestrator_path(path) \
            and payload.get("auth_mode") != "unauthenticated":
        from tools._core import session_manager as sm
        try:
            tok = activate(ctx)
            try:
                m = await asyncio.to_thread(sm.get_auth, rt, role)  # to_thread copies ctx
            finally:
                deactivate(tok)
        except sm.AuthError as e:
            return _refuse(f"Authentication for role {role or rt.cfg.get('default_role') or 'default'} "
                           f"failed: {e}", "auth_failed"), None, None
        except Exception as e:
            return _refuse(f"Authentication error: {type(e).__name__}", "auth_failed"), None, None
        if m:
            body = dict(payload)
            body.update(sm.material_to_body(m))
            new_body = json.dumps(body).encode()
    return None, ctx, new_body


async def annotate_response(response, ctx: ScanContext):
    """After a profile-scoped route ran: attach scope-enforcement stats, and
    turn a result whose EVERY outbound request was blocked into SKIPPED (so a
    fully-blocked module never reads as a clean pass)."""
    if ctx is None or ctx.blocked == 0:
        return response
    summary = ctx.summary()
    try:
        from tools.auth._db import record_audit
        await asyncio.to_thread(
            record_audit, "scan.scope_block", actor_id=ctx.user_id,
            target=ctx.path, detail=json.dumps({k: summary[k] for k in summary
                                                if k != "blocked_samples"})[:1000])
    except Exception:
        pass
    ctype = (response.headers.get("content-type") or "").lower()
    if "application/json" not in ctype:
        return response
    try:
        chunks = []
        async for c in response.body_iterator:
            chunks.append(c if isinstance(c, (bytes, bytearray)) else str(c).encode())
        raw = b"".join(chunks)
    except Exception:
        return response
    from starlette.responses import Response
    hdrs = {k: v for k, v in response.headers.items()
            if k.lower() not in ("content-length", "content-type")}
    try:
        data = json.loads(raw)
    except Exception:
        return Response(content=raw, status_code=response.status_code,
                        headers=hdrs, media_type="application/json")
    if isinstance(data, dict):
        data["scope_enforcement"] = summary
        reached = summary["in_scope"] + summary.get("subprocess_in_scope", 0)
        sp_blocked = summary.get("subprocess_blocked", 0)
        findings = data.get("findings") if isinstance(data.get("findings"), list) else []
        actionable = [f for f in findings if not isinstance(f, dict) or str(
            f.get("severity") or "").upper() not in ("POSITIVE", "INFO", "PASS", "NONE", "")]
        if sp_blocked and not summary.get("subprocess_in_scope") and not actionable:
            # SCOPE-GUARD-SUBPROC-V1: the tool's external scanner was refused
            # (out-of-scope target) and nothing else produced a real finding.
            # Drop "clean" claims and report SKIPPED, never a silent pass.
            sample = next((x for x in summary.get("blocked_samples") or []
                           if str(x.get("url", "")).startswith("subprocess:")), {})
            kept = [f for f in findings if not (isinstance(f, dict) and str(
                f.get("severity") or "").upper() in ("POSITIVE", "PASS"))]
            data["findings"] = kept
            if "total" in data:
                data["total"] = len(kept)
            cat = ("outside_window" if sample.get("category") == "blocked_outside_window"
                   else "out_of_scope")
            what = str(sample.get("url") or "subprocess: target")[len("subprocess:"):].strip()
            data.update({"status": "SKIPPED", "_skipped": True, "skipped": True,
                         "skip_category": cat, "vulnerable": False,
                         "skipped_reason": (f"External scanner not launched: {what[:200]} is "
                                            f"outside the target profile's scope/testing window "
                                            f"({sample.get('reason') or cat}); nothing was "
                                            f"tested against it.")})
        elif reached == 0 and not data.get("findings"):
            cat = ("outside_window" if summary.get("blocked_outside_window") else
                   "rate_limited" if summary.get("blocked_rate_limit") and not summary.get("blocked_out_of_scope")
                   else "out_of_scope")
            data.update({"status": "SKIPPED", "_skipped": True, "skipped": True, "skip_category": cat,
                         "vulnerable": False,
                         "skipped_reason": (f"All {summary['blocked_total']} outbound request(s) to the "
                                            f"target were blocked by the profile's scope/safety policy "
                                            f"({cat}); nothing was tested.")})
        else:
            data.setdefault("coverage_note",
                            f"{summary['blocked_total']} request(s) blocked by profile scope/safety "
                            f"policy; coverage is partial.")
    return Response(content=json.dumps(data, default=str).encode(),
                    status_code=response.status_code, headers=hdrs,
                    media_type="application/json")
