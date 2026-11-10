"""Browser session cookies (SESSION-COOKIE-V1).

The JWT used to live in localStorage, where any XSS could read and exfiltrate
it. Browsers now get it ONLY as an HttpOnly cookie that JavaScript cannot
read; API clients (CLI, API keys, internal fan-out) keep using the
``Authorization: Bearer`` header unchanged.

Cookies set on login/register:
  * ``vl_session`` — the JWT. HttpOnly, SameSite=Strict, Path=/api,
    Secure (configurable, see below). Never readable by page JS.
  * ``vl_csrf``    — random double-submit token. NOT HttpOnly (the SPA reads
    it and echoes it in the ``X-CSRF-Token`` header), SameSite=Strict,
    Path=/ (document.cookie only exposes cookies whose path covers the page).

CSRF rule (enforced in main.py's cookie-auth middleware and again in
verify_token as a fallback): a request authenticated by the cookie that uses
a state-changing method (POST/PUT/PATCH/DELETE) must carry an
``X-CSRF-Token`` header equal to the ``vl_csrf`` cookie. Bearer-header
requests are exempt (a cross-site page cannot set that header).

Env:
  VL_COOKIE_SECURE   "1" (default) always Secure; "0" never (local http dev);
                     "auto" Secure iff the request arrived over https
                     (scheme or X-Forwarded-Proto).
  VL_COOKIE_DOMAIN   optional Domain attribute (default: host-only cookie).

Underscore-prefixed -> never autoloaded as a route module.
"""
import hmac
import os
import secrets
from http.cookies import SimpleCookie
from typing import Optional

SESSION_COOKIE = "vl_session"
CSRF_COOKIE = "vl_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_PATH = "/api"
CSRF_PATH = "/"
SESSION_MAX_AGE = 7 * 24 * 3600          # matches the JWT TTL (login.py TOKEN_TTL_HOURS)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
# Unsafe-method paths that do not need the CSRF header even when a session
# cookie is present: login/register establish a NEW session (and a stale
# cookie must not block them); logout only clears cookies.
CSRF_EXEMPT_PATHS = frozenset({
    "/api/auth/login", "/api/auth/register", "/api/auth/logout",
})


def _secure_mode() -> str:
    return (os.getenv("VL_COOKIE_SECURE", "1") or "1").strip().lower()


def cookie_secure(request=None) -> bool:
    mode = _secure_mode()
    if mode in ("0", "false", "no", "off"):
        return False
    if mode == "auto":
        if request is None:
            return True
        try:
            xf = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
            return xf == "https" or request.url.scheme == "https"
        except Exception:
            return True
    return True


def _domain() -> Optional[str]:
    d = (os.getenv("VL_COOKIE_DOMAIN") or "").strip()
    return d or None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_session_cookies(response, token: str, request=None,
                        csrf_token: Optional[str] = None) -> str:
    """Attach vl_session (HttpOnly JWT) + vl_csrf to `response`. Returns the
    CSRF token so the caller can also hand it to the SPA in the JSON body."""
    secure = cookie_secure(request)
    csrf = csrf_token or new_csrf_token()
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, path=SESSION_PATH,
                        domain=_domain(), secure=secure, httponly=True, samesite="strict")
    response.set_cookie(CSRF_COOKIE, csrf, max_age=SESSION_MAX_AGE, path=CSRF_PATH,
                        domain=_domain(), secure=secure, httponly=False, samesite="strict")
    return csrf


def set_csrf_cookie(response, request=None, csrf_token: Optional[str] = None) -> str:
    csrf = csrf_token or new_csrf_token()
    response.set_cookie(CSRF_COOKIE, csrf, max_age=SESSION_MAX_AGE, path=CSRF_PATH,
                        domain=_domain(), secure=cookie_secure(request), httponly=False,
                        samesite="strict")
    return csrf


def clear_session_cookies(response, request=None) -> None:
    secure = cookie_secure(request)
    response.delete_cookie(SESSION_COOKIE, path=SESSION_PATH, domain=_domain(),
                           secure=secure, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path=CSRF_PATH, domain=_domain(),
                           secure=secure, httponly=False, samesite="strict")


def parse_cookie_header(raw: str) -> dict:
    out = {}
    if not raw:
        return out
    try:
        sc = SimpleCookie()
        sc.load(raw)
        for k, m in sc.items():
            out[k] = m.value
    except Exception:
        # Fall back to a tolerant split (SimpleCookie rejects some real-world
        # cookie strings set by other apps on the same host).
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out.setdefault(k.strip(), v.strip())
    return out


def csrf_ok(method: str, path: str, cookie_value: Optional[str],
            header_value: Optional[str]) -> bool:
    """Double-submit check for a COOKIE-authenticated request."""
    if (method or "").upper() in SAFE_METHODS:
        return True
    if (path or "") in CSRF_EXEMPT_PATHS:
        return True
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(str(cookie_value), str(header_value))


_BOGUS_BEARERS = {"", "null", "undefined", "none", "__vl_cookie_session__"}


def real_bearer(header_value: Optional[str]) -> Optional[str]:
    """Return the bearer token from an Authorization header value, or None
    when it is absent/placeholder ("Bearer ", "Bearer null", the SPA's
    cookie-session sentinel)."""
    if not header_value:
        return None
    v = header_value.strip()
    if not v.lower().startswith("bearer"):
        return None
    tok = v[6:].strip()
    if tok.lower() in _BOGUS_BEARERS:
        return None
    return tok
