"""POST /api/scan/login -- automate login on the CUSTOMER's target.

Form mode falls back to SPA / JSON-API mode automatically when the
target is an Angular/React/Vue app (no <form> tag, or form POST does
not actually authenticate). Captures both cookie AND bearer token.
"""
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_scan_quota, _BROWSER_HEADERS

router = APIRouter()


# UNDERSCORE-RESOLVE-V1 — Tomcat (WebGoat) rejects underscore hostnames
# per RFC 9112. Resolve to IP first so Host header doesn't carry underscore.
import socket as _socket
def _resolve_underscore(url: str) -> str:
    try:
        from urllib.parse import urlparse as _up
        pp = _up(url)
        if pp.hostname and "_" in pp.hostname:
            ip = _socket.gethostbyname(pp.hostname)
            return url.replace(pp.hostname, ip)
    except Exception:
        pass
    return url


_USERNAME_FIELDS = ("username", "user", "email", "login", "userid",
                    "user_id", "user_name", "email_address", "j_username")
_PASSWORD_FIELDS = ("password", "passwd", "pass", "pwd", "j_password")
_CSRF_FIELDS = ("csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token",
                "_token", "csrf", "__RequestVerificationToken")
_LOGIN_PAGE_MARKERS = ("login", "sign in", "sign-in", "signin",
                       "log in", "log-in", "password", "username")

_SPA_LOGIN_PATHS = (
    "/rest/user/login", "/api/auth/login", "/api/login", "/auth/login",
    "/api/v1/auth/login", "/api/v1/login", "/login/api",
    "/user/login", "/users/login", "/sessions", "/api/sessions",
)

# WEBGOAT-AUTOREG-V1 — labs that require self-registration before login.
# When the login fails AND the URL matches one of these patterns, the
# backend tries to register the user via the matching register endpoint
# THEN retries login. Customers using internal labs (lab_webgoat,
# lab_juiceshop) get auto-onboarding instead of "user not found" errors.
_SELF_REGISTER_LABS = [
    {
        "name": "webgoat",
        "url_match": "webgoat",
        "register_url": "/WebGoat/register.mvc",
        "fields": lambda u, p: {
            "username": u, "password": p, "matchingPassword": p, "agree": "agree",
        },
    },
    {
        "name": "juiceshop",
        "url_match": "lab_juiceshop",
        "register_url": "/api/Users/",
        "json": True,
        "fields": lambda u, p: {
            "email": u, "password": p, "passwordRepeat": p, "securityQuestion": {
                "id": 1, "question": "Your eldest siblings middle name?",
            }, "securityAnswer": "test",
        },
    },
]


def _try_self_register(target: str, login_url: str, user: str, pwd: str,
                       sess: requests.Session) -> bool:
    """If target matches a known self-register lab (WebGoat / Juice Shop),
    POST the register endpoint to bootstrap the user. Returns True if
    register call succeeded (HTTP 200/201/302/409=already-exists)."""
    full = f"{target} {login_url}".lower()
    for lab in _SELF_REGISTER_LABS:
        if lab["url_match"] not in full:
            continue
        reg_url = _abs(target, lab["register_url"])
        try:
            body = lab["fields"](user, pwd)
            if lab.get("json"):
                r = sess.post(reg_url, json=body, timeout=8, verify=False,
                              allow_redirects=True)
            else:
                r = sess.post(reg_url, data=body, timeout=8, verify=False,
                              allow_redirects=True)
            # 200/201/302 = newly created; 409/400 (with "exists") = already there
            if r.status_code in (200, 201, 302):
                return True
            if r.status_code in (400, 409) and (
                "exist" in (r.text or "").lower()
                or "duplicate" in (r.text or "").lower()
            ):
                return True
        except Exception:
            pass
    return False
_BEARER_JSON_PATHS = (
    ("token",), ("access_token",), ("accessToken",), ("jwt",),
    ("authentication", "token"), ("data", "token"),
    ("data", "access_token"), ("auth", "token"), ("result", "token"),
)


class ScanLoginRequest(BaseModel):
    target: str
    login_url: str
    username: str
    password: str
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    success_indicator: Optional[str] = None
    success_text: Optional[str] = None
    extra_fields: Optional[dict] = None
    auth_type: str = "form"
    bearer_token: Optional[str] = None


def _abs(target: str, maybe_path: str) -> str:
    if not maybe_path:
        return target
    if maybe_path.startswith(("http://", "https://")):
        return maybe_path
    return urljoin(target.rstrip("/") + "/", maybe_path.lstrip("/"))


def _looks_like_login_page(body: str) -> bool:
    low = body.lower()[:5000]
    return ("<form" in low and "password" in low) or \
           sum(1 for m in _LOGIN_PAGE_MARKERS if m in low) >= 3


def _scrape_hidden_inputs(html: str) -> dict:
    import re
    out = {}
    for m in re.finditer(r'<input\b[^>]*\btype=["\']hidden["\'][^>]*>', html, re.IGNORECASE):
        tag = m.group(0)
        name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        if name_m:
            out[name_m.group(1)] = val_m.group(1) if val_m else ""
    return out


def _detect_field(form_inputs: dict, candidates: tuple) -> Optional[str]:
    keys_lower = {k.lower(): k for k in form_inputs.keys()}
    for c in candidates:
        if c in keys_lower:
            return keys_lower[c]
    return None


def _extract_bearer(data) -> Optional[str]:
    if not isinstance(data, dict):
        return None
    for path in _BEARER_JSON_PATHS:
        cur = data
        ok = True
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok and isinstance(cur, str) and len(cur) > 16:
            return cur
    return None


def _try_spa_login(target: str, username: str, password: str,
                    explicit_path: Optional[str] = None,
                    deadline: float = 0) -> Optional[dict]:
    sess = requests.Session()
    sess.headers.update(_BROWSER_HEADERS)
    sess.headers["Content-Type"] = "application/json"
    sess.headers["Accept"] = "application/json"
    sess.verify = False

    paths = []
    if explicit_path:
        paths.append(explicit_path if explicit_path.startswith("/") else "/" + explicit_path)
    for p in _SPA_LOGIN_PATHS:
        if p not in paths:
            paths.append(p)

    body_variants = (
        {"email": username, "password": password},
        {"username": username, "password": password},
        {"user": username, "password": password},
        {"login": username, "password": password},
    )

    for path in paths:
        url = _abs(target, path)
        for body in body_variants:
            try:
                r = sess.post(url, json=body, timeout=10, allow_redirects=False)
            except Exception:
                continue
            if r.status_code >= 400:
                continue
            try:
                data = r.json()
            except Exception:
                data = None
            bearer = _extract_bearer(data) if data else None
            cookie_header = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
            if bearer or cookie_header:
                return {
                    "auth_type": "spa",
                    "auth_cookie": cookie_header or None,
                    "auth_bearer": bearer,
                    "login_verified": True,
                    "login_url": url,
                    "post_login_status": r.status_code,
                    "verified_via": url,
                    "verified_status": r.status_code,
                    "still_on_login_page": False,
                    "cookie_names": [c.name for c in sess.cookies],
                    "spa_payload_used": list(body.keys()),
                    "hint": None,
                }
    return None


def _scrape_submit_inputs(html: str) -> dict:
    """Pick up <input type=submit name=X value=Y> -- DVWA, MediaWiki, and
    a few legacy PHP apps require the submit button's name/value in the
    POST body or the login is rejected.  DVWA-FIX-V1"""
    import re
    out = {}
    for m in re.finditer(r'<input\b[^>]*\btype=["\']submit["\'][^>]*>', html, re.IGNORECASE):
        tag = m.group(0)
        name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        val_m  = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        if name_m:
            out[name_m.group(1)] = val_m.group(1) if val_m else ""
    return out


def _scrape_form_inputs(html: str) -> dict:
    import re
    out = {}
    for m in re.finditer(r'<(?:input|select|textarea)\b[^>]*>', html, re.IGNORECASE):
        tag = m.group(0)
        name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        val_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        if name_m:
            out[name_m.group(1)] = val_m.group(1) if val_m else ""
    return out


@router.post("/api/scan/login")
async def scan_login(req: ScanLoginRequest, _=Depends(verify_scan_quota)):
    """Authenticate against the target and return captured session.
    Hard 30-second wall-clock budget — login MUST complete or fail in 30s.
    """
    import time as _time
    deadline = _time.monotonic() + 30.0

    target = req.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # ── Bearer mode ──
    if req.auth_type == "bearer":
        if not req.bearer_token:
            raise HTTPException(400, "bearer_token required when auth_type=bearer")
        check_url = _abs(target, req.success_indicator or "/")
        try:
            r = requests.get(check_url, headers={
                **_BROWSER_HEADERS,
                "Authorization": f"Bearer {req.bearer_token}",
            }, timeout=8, verify=False, allow_redirects=True)
        except Exception as e:
            raise HTTPException(502, f"Verification request failed: {e}")
        verified = (r.status_code < 400) and not _looks_like_login_page(r.text or "")
        return {
            "ok": verified, "auth_type": "bearer",
            "auth_bearer": req.bearer_token, "auth_cookie": None,
            "login_verified": verified, "verified_via": check_url,
            "verified_status": r.status_code,
            "hint": None if verified else "Token did not grant access — check token validity / expiry.",
        }

    # ── Basic auth mode ──
    if req.auth_type == "basic":
        import base64
        tok = base64.b64encode(f"{req.username}:{req.password}".encode()).decode()
        check_url = _abs(target, req.success_indicator or "/")
        try:
            r = requests.get(check_url, headers={
                **_BROWSER_HEADERS, "Authorization": f"Basic {tok}",
            }, timeout=8, verify=False, allow_redirects=True)
        except Exception as e:
            raise HTTPException(502, f"Verification request failed: {e}")
        verified = r.status_code < 400
        return {
            "ok": verified, "auth_type": "basic",
            "auth_basic": tok, "auth_cookie": None,
            "login_verified": verified, "verified_via": check_url,
            "verified_status": r.status_code,
            "hint": None if verified else "Basic auth rejected — check username/password.",
        }

    # ── Form mode (default) ──
    if req.auth_type != "form":
        raise HTTPException(400, f"Unknown auth_type: {req.auth_type}")

    login_url = _abs(target, req.login_url)
    sess = requests.Session()
    sess.headers.update(_BROWSER_HEADERS)
    sess.verify = False

    # WEBGOAT-AUTOREG-V1 — for known self-register labs, register the user
    # FIRST so the subsequent login can succeed. No-op if user already exists.
    _registered = _try_self_register(target, login_url, req.username,
                                     req.password, sess)

    # 1. GET login page for hidden fields / CSRF
    try:
        page = sess.get(login_url, timeout=8, allow_redirects=True)
    except Exception as e:
        spa = _try_spa_login(target, req.username, req.password, deadline=deadline)
        if spa is not None:
            return {"ok": True, **spa, "fallback": "spa_after_page_unreachable"}
        raise HTTPException(502, f"Could not fetch login page: {e}")

    if page.status_code >= 400:
        spa = _try_spa_login(target, req.username, req.password, deadline=deadline)
        if spa is not None:
            return {"ok": True, **spa, "fallback": f"spa_after_page_{page.status_code}"}
        raise HTTPException(502, f"Login page returned HTTP {page.status_code}")

    hidden = _scrape_hidden_inputs(page.text or "")
    all_inputs = _scrape_form_inputs(page.text or "")

    if not all_inputs:
        spa = _try_spa_login(target, req.username, req.password, deadline=deadline)
        if spa is not None:
            return {"ok": True, **spa, "fallback": "spa_no_form_on_page"}

    u_field = req.username_field or _detect_field(all_inputs, _USERNAME_FIELDS) or "username"
    p_field = req.password_field or _detect_field(all_inputs, _PASSWORD_FIELDS) or "password"

    payload = dict(hidden)
    payload[u_field] = req.username
    payload[p_field] = req.password
    if req.extra_fields:
        payload.update(req.extra_fields)

    try:
        resp = sess.post(login_url, data=payload, timeout=8, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, f"Login POST failed: {e}")

    verify_url = _abs(target, req.success_indicator or "/")
    try:
        check = sess.get(verify_url, timeout=8, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, f"Verification request failed: {e}")

    body = check.text or ""
    looks_login = _looks_like_login_page(body)
    text_match = (req.success_text in body) if req.success_text else True
    verified = (check.status_code < 400) and (not looks_login) and text_match

    if not verified:
        spa = _try_spa_login(target, req.username, req.password, deadline=deadline)
        if spa is not None:
            return {"ok": True, **spa, "fallback": "spa_after_form_unverified"}

    cookie_header = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)

    return {
        "ok": verified, "auth_type": "form",
        "auth_cookie": cookie_header or None, "auth_bearer": None,
        "login_verified": verified, "login_url": login_url,
        "username_field_used": u_field, "password_field_used": p_field,
        "hidden_fields_captured": list(hidden.keys()),
        "post_login_status": resp.status_code,
        "verified_via": verify_url, "verified_status": check.status_code,
        "still_on_login_page": looks_login,
        "cookie_names": [c.name for c in sess.cookies],
        "self_registered": _registered,
        "hint": (None if verified else
                 ("Login failed even after auto-register attempt. " if _registered
                  else "Login failed. ")
                 + "Check: (a) username/password, (b) field names "
                 "(try setting username_field / password_field), "
                 "(c) CSRF protection requiring JS, or (d) MFA/captcha (not supported). "
                 "For WebGoat/Juice Shop, the auto-register flow should bootstrap a "
                 "user automatically - if it didn't, the lab may not be reachable."),
    }


def register(app):
    app.include_router(router)
