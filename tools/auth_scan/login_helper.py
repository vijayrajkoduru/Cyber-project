"""POST /api/scan/login -- automate login on the CUSTOMER's target.

Flow:
  1. Customer enters: login URL, username, password (and optionally field
     names + a success indicator).
  2. We submit the login form using a requests.Session so the server's
     Set-Cookie is captured (incl. cookies set across redirects).
  3. We hit a follow-up URL (the success_indicator) with the captured
     session to verify the login actually took effect.
  4. We return the captured `auth_cookie` (and any Authorization bearer if
     the app uses one) so the frontend can pass it into every subsequent
     /api/scan/* call. The existing _shared.make_req_headers() already
     knows how to thread these into every HTTP request the scanners make.

We DO NOT persist credentials. They live only inside this single request.
"""
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_scan_quota, _BROWSER_HEADERS

router = APIRouter()


# ── Heuristics for autodetecting the login form fields ────────────────
_USERNAME_FIELDS = ("username", "user", "email", "login", "userid",
                    "user_id", "user_name", "email_address", "j_username")
_PASSWORD_FIELDS = ("password", "passwd", "pass", "pwd", "j_password")
_CSRF_FIELDS = ("csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token",
                "_token", "csrf", "__RequestVerificationToken")
_LOGIN_PAGE_MARKERS = ("login", "sign in", "sign-in", "signin",
                       "log in", "log-in", "password", "username")


class ScanLoginRequest(BaseModel):
    target: str                                    # e.g. https://app.example.com
    login_url: str                                 # absolute or path, e.g. /login
    username: str
    password: str
    username_field: Optional[str] = None           # override autodetect
    password_field: Optional[str] = None           # override autodetect
    success_indicator: Optional[str] = None        # URL path to GET after login
                                                   # (default = / on the target)
    success_text: Optional[str] = None             # substring expected in body
                                                   # of success_indicator response
    extra_fields: Optional[dict] = None            # any hidden inputs the form
                                                   # needs (e.g. _csrf overrides)
    auth_type: str = "form"                        # form | basic | bearer
    bearer_token: Optional[str] = None             # for auth_type=bearer


def _abs(target: str, maybe_path: str) -> str:
    """Resolve a relative path against the target's origin."""
    if not maybe_path:
        return target
    if maybe_path.startswith(("http://", "https://")):
        return maybe_path
    return urljoin(target.rstrip("/") + "/", maybe_path.lstrip("/"))


def _looks_like_login_page(body: str) -> bool:
    """If the response after login still looks like a login form, we
    probably failed (wrong creds, CSRF mismatch, etc.)."""
    low = body.lower()[:5000]
    return ("<form" in low and "password" in low) or \
           sum(1 for m in _LOGIN_PAGE_MARKERS if m in low) >= 3


def _scrape_hidden_inputs(html: str) -> dict:
    """Pull <input type=hidden name=X value=Y> for CSRF tokens etc.
    Regex-only on purpose -- avoids beautifulsoup dependency."""
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
    """Pick the first form input name that matches any candidate."""
    keys_lower = {k.lower(): k for k in form_inputs.keys()}
    for c in candidates:
        if c in keys_lower:
            return keys_lower[c]
    return None


def _scrape_form_inputs(html: str) -> dict:
    """All input/select/textarea names found on the page (best-effort)."""
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
    """Authenticate the scanner against the customer's target and return
    the captured session as `auth_cookie` ready to drop into ScanRequest.
    """
    target = req.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # ── Bearer mode -- customer already has a token; just verify it ──
    if req.auth_type == "bearer":
        if not req.bearer_token:
            raise HTTPException(400, "bearer_token required when auth_type=bearer")
        check_url = _abs(target, req.success_indicator or "/")
        try:
            r = requests.get(check_url, headers={
                **_BROWSER_HEADERS,
                "Authorization": f"Bearer {req.bearer_token}",
            }, timeout=15, verify=False, allow_redirects=True)
        except Exception as e:
            raise HTTPException(502, f"Verification request failed: {e}")
        verified = (r.status_code < 400) and not _looks_like_login_page(r.text or "")
        return {
            "ok": verified,
            "auth_type": "bearer",
            "auth_bearer": req.bearer_token,
            "auth_cookie": None,
            "login_verified": verified,
            "verified_via": check_url,
            "verified_status": r.status_code,
            "hint": None if verified else
                    "Token did not grant access -- check token validity / expiry.",
        }

    # ── Basic auth mode -- no form, just encode and verify ──
    if req.auth_type == "basic":
        import base64
        token = base64.b64encode(f"{req.username}:{req.password}".encode()).decode()
        check_url = _abs(target, req.success_indicator or "/")
        try:
            r = requests.get(check_url, headers={
                **_BROWSER_HEADERS,
                "Authorization": f"Basic {token}",
            }, timeout=15, verify=False, allow_redirects=True)
        except Exception as e:
            raise HTTPException(502, f"Verification request failed: {e}")
        verified = r.status_code < 400
        return {
            "ok": verified,
            "auth_type": "basic",
            "auth_basic": token,
            "auth_cookie": None,
            "login_verified": verified,
            "verified_via": check_url,
            "verified_status": r.status_code,
            "hint": None if verified else
                    "Basic auth rejected -- check username/password.",
        }

    # ── Form mode (default) ──
    if req.auth_type != "form":
        raise HTTPException(400, f"Unknown auth_type: {req.auth_type}")

    login_url = _abs(target, req.login_url)
    sess = requests.Session()
    sess.headers.update(_BROWSER_HEADERS)
    sess.verify = False

    # 1. GET the login page so we can scrape hidden fields (CSRF tokens etc.)
    try:
        page = sess.get(login_url, timeout=15, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, f"Could not fetch login page: {e}")

    if page.status_code >= 400:
        raise HTTPException(502, f"Login page returned HTTP {page.status_code}")

    hidden = _scrape_hidden_inputs(page.text or "")
    all_inputs = _scrape_form_inputs(page.text or "")

    # 2. Determine which field name carries username / password
    u_field = req.username_field or _detect_field(all_inputs, _USERNAME_FIELDS) or "username"
    p_field = req.password_field or _detect_field(all_inputs, _PASSWORD_FIELDS) or "password"

    # 3. Build payload -- hidden fields + creds + any extras from caller
    payload = dict(hidden)
    payload[u_field] = req.username
    payload[p_field] = req.password
    if req.extra_fields:
        payload.update(req.extra_fields)

    # 4. POST credentials. allow_redirects=True so we follow the post-login
    #    redirect and pick up any cookies set during the redirect chain.
    try:
        resp = sess.post(login_url, data=payload, timeout=15, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, f"Login POST failed: {e}")

    # 5. Verify -- hit success_indicator (or '/') with the session and check
    #    we no longer see a login form.
    verify_url = _abs(target, req.success_indicator or "/")
    try:
        check = sess.get(verify_url, timeout=15, allow_redirects=True)
    except Exception as e:
        raise HTTPException(502, f"Verification request failed: {e}")

    body = check.text or ""
    looks_login = _looks_like_login_page(body)
    text_match = (req.success_text in body) if req.success_text else True
    verified = (check.status_code < 400) and (not looks_login) and text_match

    # 6. Serialize cookies to a single header string the scanners can reuse.
    cookie_header = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)

    return {
        "ok": verified,
        "auth_type": "form",
        "auth_cookie": cookie_header or None,
        "auth_bearer": None,
        "login_verified": verified,
        "login_url": login_url,
        "username_field_used": u_field,
        "password_field_used": p_field,
        "hidden_fields_captured": list(hidden.keys()),
        "post_login_status": resp.status_code,
        "verified_via": verify_url,
        "verified_status": check.status_code,
        "still_on_login_page": looks_login,
        "cookie_names": [c.name for c in sess.cookies],
        "hint": (
            None if verified else
            "Login appears to have failed. Check: (a) username/password, "
            "(b) field names (try setting username_field / password_field), "
            "(c) CSRF protection requiring JS, or (d) MFA/captcha (not "
            "supported by automated login)."
        ),
    }


def register(app):
    app.include_router(router)
