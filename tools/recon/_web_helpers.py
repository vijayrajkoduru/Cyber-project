"""_web_helpers — shared HTTP utilities for tier5_web scanners.

AUTHED-RECON-V1 (2026-06-06): customer-provided login session is injected
into every HTTP request via contextvars. Web-facing scanners only need to
call set_auth_from_req(req) once at the endpoint top — fetch() reads the
contextvar and adds Cookie / Authorization headers automatically.

This lets the customer paste login creds ONCE on the dashboard, our backend
performs the login via /api/scan/login, then every authenticated-eligible
recon scanner crawls the post-login surface (admin panels, /api/me,
authenticated dashboards) instead of being stuck on the public login page.
"""
import asyncio, contextvars, ssl, urllib.request, urllib.error

UA = "VulnusLab-Recon/1.0"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # allow self-signed for probes

# Per-request contextvars. Set by endpoint via set_auth_from_req(); read by
# fetch(). contextvars are async-task-local so concurrent scans don't leak
# sessions between customers' tenants.
_AUTH_COOKIE: contextvars.ContextVar = contextvars.ContextVar(
    "recon_auth_cookie", default=None)
_AUTH_BEARER: contextvars.ContextVar = contextvars.ContextVar(
    "recon_auth_bearer", default=None)


def set_auth_from_req(req) -> bool:
    """Pull auth_cookie / auth_bearer off the incoming ScanRequest and stash
    in contextvars so fetch() picks them up. Returns True if any auth was set.

    Call this as the FIRST line of any web-facing scanner endpoint:

        @router.post("/api/recon/crawl_endpoints")
        async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
            set_auth_from_req(req)   # <-- one line; rest unchanged
            host = recon_host(req.target)
            return await run_scanner(...)
    """
    set_any = False
    c = getattr(req, "auth_cookie", None)
    if c:
        _AUTH_COOKIE.set(c)
        set_any = True
    b = getattr(req, "auth_bearer", None)
    if b:
        _AUTH_BEARER.set(b)
        set_any = True
    return set_any


def current_auth() -> dict:
    """Read the current request's auth state. Used by gather() for diagnostics
    (e.g. tag endpoints as 'requires auth' vs 'public')."""
    return {
        "auth_cookie": _AUTH_COOKIE.get(),
        "auth_bearer": _AUTH_BEARER.get(),
        "is_authed":   bool(_AUTH_COOKIE.get() or _AUTH_BEARER.get()),
    }


def _normalize(target):
    t = target.strip()
    if not t.startswith(("http://","https://")):
        t = "https://" + t
    return t.rstrip("/")

async def fetch(url, method="GET", headers=None, body=None, timeout=4):
    """Returns (status_code, headers_dict, body_bytes). 0 status on error.

    Auto-injects Cookie / Authorization from the contextvars set by
    set_auth_from_req(). Caller's explicit headers WIN if the same key is
    supplied (so a scanner forcing a specific Cookie still works)."""
    hd = {"User-Agent": UA}
    # Inject customer's session if endpoint registered one.
    ac = _AUTH_COOKIE.get()
    ab = _AUTH_BEARER.get()
    if ac:
        hd["Cookie"] = ac
    if ab:
        hd["Authorization"] = f"Bearer {ab}"
    if headers: hd.update(headers)
    def _do():
        try:
            req = urllib.request.Request(url, method=method, headers=hd, data=body)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, dict(r.headers), r.read(128*1024)
        except urllib.error.HTTPError as e:
            try: bb = e.read(128*1024)
            except Exception: bb = b""
            return e.code, dict(e.headers or {}), bb
        except Exception:
            return 0, {}, b""
    return await asyncio.to_thread(_do)

def base_url(host):
    return _normalize(host)
