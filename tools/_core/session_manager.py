"""Session manager — turn a target-profile auth role into request auth material
(SESSION-MANAGER-V1, CUSTOMER mode).

Pluggable providers (one per `provider` value in a profile role):

    form_login                 HTML form login (CSRF hidden-field scrape + submit
                               button field, reusing tools/auth_scan/login_helper),
                               JSON-API fallback on the SAME login_url only.
                               NO lab bootstrap / self-register / un-hardening —
                               those stay LAB-only in login_helper.scan_login.
    bearer_token               static bearer token
    api_key_header             static API key in a named header
    cookie                     static Cookie header
    basic_auth                 HTTP Basic
    oauth2_client_credentials  client-credentials grant against token_url

Material shape (what scans consume):
    {"cookie": str|None, "bearer": str|None, "headers": {name: value},
     "role": str, "provider": str, "obtained_at": float, "expires_at": float,
     "verified": True|False|None, "detail": str}

Sessions are cached in memory per (profile_id, role) with a TTL (role
`session_ttl_sec`, or the OAuth token lifetime). If the role has a
`logged_in_indicator` ({url, regex, negative_regex, check_interval_sec}), the
cached session is re-validated at most every check_interval_sec and a re-login
happens automatically when it no longer looks logged in.

Every request made here goes through the normal `requests` stack, so the scope
guard (tools/_core/scope_guard.py) applies: the login URL must be in scope. The
one exception is the configured auth endpoint host (e.g. an external IdP
token_url), which is allowed for the duration of the login only.
"""
import base64
import logging
import re
import threading
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("vulnuslab.session_manager")

_TIMEOUT = 15


class AuthError(Exception):
    """Login / token acquisition failed. Message is safe to show to the user
    (never contains secrets)."""


def _hs(v):
    if not isinstance(v, str):
        return v
    return v.replace("\r", "").replace("\n", "").replace("\x00", "")


def _browser_headers() -> dict:
    try:
        from tools._shared import _BROWSER_HEADERS
        return dict(_BROWSER_HEADERS)
    except Exception:
        return {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}


def base_url(rt) -> str:
    """Base URL for relative auth URLs: the profile's first URL-ish primary target."""
    for t in rt.cfg.get("primary_targets") or []:
        if "://" in t:
            p = urlparse(t)
            return f"{p.scheme}://{p.netloc}"
    for t in rt.cfg.get("primary_targets") or []:
        if "/" not in t:              # bare host (not a CIDR)
            return "https://" + t
    return ""


def _abs(base: str, maybe: str) -> str:
    if not maybe:
        return base or ""
    if maybe.startswith(("http://", "https://")):
        return maybe
    return urljoin((base or "").rstrip("/") + "/", maybe.lstrip("/"))


def _new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(_browser_headers())
    s.verify = False
    return s


def _material(role: dict, *, cookie=None, bearer=None, headers=None,
              ttl: Optional[float] = None, detail: str = "", verified=None) -> dict:
    hdrs = {}
    for k, v in (role.get("extra_headers") or {}).items():
        hdrs[k] = _hs(v)
    for k, v in (headers or {}).items():
        hdrs[k] = _hs(v)
    now = time.time()
    return {
        "cookie": _hs(cookie) or None,
        "bearer": _hs(bearer) or None,
        "headers": hdrs,
        "role": role.get("role"),
        "provider": role.get("provider"),
        "obtained_at": now,
        "expires_at": now + float(ttl or role.get("session_ttl_sec") or 1800),
        "verified": verified,
        "detail": detail,
    }


def apply_material(material: dict, session: Optional[requests.Session] = None,
                   headers: Optional[dict] = None) -> dict:
    """Merge auth material into a header dict (and optionally a Session)."""
    h = dict(headers or {})
    if material.get("cookie"):
        h["Cookie"] = material["cookie"]
    if material.get("bearer"):
        h["Authorization"] = f"Bearer {material['bearer']}"
    h.update(material.get("headers") or {})
    if session is not None:
        session.headers.update(h)
    return h


# ── Providers ──────────────────────────────────────────────────────
def _p_bearer(rt, role) -> dict:
    return _material(role, bearer=role.get("token"), detail="static bearer token")


def _p_api_key(rt, role) -> dict:
    return _material(role, headers={role["header_name"]: role.get("api_key")},
                     detail=f"API key in header {role['header_name']}")


def _p_cookie(rt, role) -> dict:
    return _material(role, cookie=role.get("cookie"), detail="static cookie")


def _p_basic(rt, role) -> dict:
    tok = base64.b64encode(f"{role.get('username', '')}:{role.get('password', '')}".encode()).decode()
    return _material(role, headers={"Authorization": f"Basic {tok}"}, detail="HTTP Basic")


def _p_oauth2_cc(rt, role) -> dict:
    url = _abs(base_url(rt), role["token_url"])
    data = {"grant_type": "client_credentials", "client_id": role["client_id"],
            "client_secret": role.get("client_secret") or ""}
    if role.get("oauth_scope"):
        data["scope"] = role["oauth_scope"]
    if role.get("audience"):
        data["audience"] = role["audience"]
    try:
        r = requests.post(url, data=data, timeout=_TIMEOUT, verify=False,
                          headers={"Accept": "application/json"}, allow_redirects=False)
    except Exception as e:
        raise AuthError(f"token endpoint unreachable: {type(e).__name__}")
    if r.status_code >= 400:
        raise AuthError(f"token endpoint returned HTTP {r.status_code}")
    try:
        js = r.json()
    except Exception:
        raise AuthError("token endpoint did not return JSON")
    tok = js.get("access_token") if isinstance(js, dict) else None
    if not tok:
        raise AuthError("token endpoint response has no access_token")
    ttl = None
    try:
        ttl = max(60.0, float(js.get("expires_in")) - 30.0)
    except Exception:
        pass
    ttype = str(js.get("token_type") or "bearer").lower()
    if ttype not in ("bearer", ""):
        return _material(role, headers={"Authorization": f"{js.get('token_type')} {tok}"},
                         ttl=ttl, detail="oauth2 client_credentials")
    return _material(role, bearer=tok, ttl=ttl, detail="oauth2 client_credentials")


def _p_form_login(rt, role) -> dict:
    from tools.auth_scan.login_helper import (
        _scrape_hidden_inputs, _scrape_form_inputs, _detect_field,
        _looks_like_login_page, _extract_bearer, _USERNAME_FIELDS, _PASSWORD_FIELDS,
    )
    base = base_url(rt)
    login_url = _abs(base, role["login_url"])
    sess = _new_session()
    try:
        page = sess.get(login_url, timeout=_TIMEOUT, allow_redirects=True)
    except Exception as e:
        raise AuthError(f"could not fetch login page: {type(e).__name__}")
    html = (page.text or "") if page.status_code < 400 else ""
    all_inputs = _scrape_form_inputs(html)
    hidden = _scrape_hidden_inputs(html)
    username, password = role.get("username") or "", role.get("password") or ""

    if all_inputs:
        # SUBMIT-FIELD-V1 parity: post every named form field (includes the
        # submit button + CSRF hidden inputs), then overlay credentials.
        u_field = role.get("username_field") or _detect_field(all_inputs, _USERNAME_FIELDS) or "username"
        p_field = role.get("password_field") or _detect_field(all_inputs, _PASSWORD_FIELDS) or "password"
        payload = dict(all_inputs)
        payload.update(hidden)
        payload[u_field] = username
        payload[p_field] = password
        payload.update(role.get("extra_fields") or {})
        action = login_url
        m = re.search(r'<form\b[^>]*\baction=["\']([^"\']*)["\']', html, re.I)
        if m and m.group(1).strip() and not m.group(1).strip().lower().startswith("javascript:"):
            action = urljoin(page.url or login_url, m.group(1).strip())
        try:
            resp = sess.post(action, data=payload, timeout=_TIMEOUT, allow_redirects=True)
        except Exception as e:
            raise AuthError(f"login POST failed: {type(e).__name__}")
        bearer = None
        try:
            bearer = _extract_bearer(resp.json())
        except Exception:
            pass
        body = resp.text or ""
        looks_login = _looks_like_login_page(body)
        if role.get("success_text") and role["success_text"] not in body and not bearer:
            raise AuthError("login did not succeed (success_text not found after POST)")
        if resp.status_code >= 400:
            raise AuthError(f"login POST returned HTTP {resp.status_code}")
        cookie = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
        if not cookie and not bearer:
            raise AuthError("login returned no session cookie or token")
        return _material(role, cookie=cookie, bearer=bearer,
                         verified=None if role.get("logged_in_indicator") else (not looks_login),
                         detail="form login" + (" (still looks like login page)" if looks_login else ""))

    # No HTML form: JSON API login on the SAME login_url only (one attempt per
    # body shape at most 2 — never sprays alternate paths on a customer site,
    # to avoid account lockout).
    u_field = role.get("username_field") or ""
    p_field = role.get("password_field") or "password"
    bodies = ([{u_field: username, p_field: password}] if u_field else
              [{"username": username, p_field: password}, {"email": username, p_field: password}])
    last = None
    for b in bodies:
        b.update(role.get("extra_fields") or {})
        try:
            r = sess.post(login_url, json=b, timeout=_TIMEOUT, allow_redirects=False,
                          headers={"Accept": "application/json"})
        except Exception as e:
            last = f"{type(e).__name__}"
            continue
        last = f"HTTP {r.status_code}"
        if r.status_code >= 400:
            continue
        bearer = None
        try:
            bearer = _extract_bearer(r.json())
        except Exception:
            pass
        cookie = "; ".join(f"{c.name}={c.value}" for c in sess.cookies)
        if bearer or cookie:
            return _material(role, cookie=cookie or None, bearer=bearer, detail="JSON API login")
    raise AuthError(f"login failed (no form on login page; JSON login {last})")


PROVIDERS = {
    "form_login": _p_form_login,
    "bearer_token": _p_bearer,
    "api_key_header": _p_api_key,
    "cookie": _p_cookie,
    "basic_auth": _p_basic,
    "oauth2_client_credentials": _p_oauth2_cc,
}


# ── Validity check ─────────────────────────────────────────────────
def check_session(rt, role: dict, material: dict) -> Optional[bool]:
    """True/False if the role has a logged_in_indicator, else None (unknown)."""
    ind = role.get("logged_in_indicator") or {}
    if not ind or not (ind.get("url") or ind.get("regex")):
        return None
    url = _abs(base_url(rt), ind.get("url") or "/")
    h = apply_material(material, headers=_browser_headers())
    try:
        r = requests.get(url, headers=h, timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return False
    if r is None or r.status_code >= 400:
        return False
    body = (r.text or "")[:500000]
    if ind.get("negative_regex") and re.search(ind["negative_regex"], body, re.I):
        return False
    if ind.get("regex"):
        return bool(re.search(ind["regex"], body, re.I))
    from tools.auth_scan.login_helper import _looks_like_login_page
    return not _looks_like_login_page(body)


# ── Cache ──────────────────────────────────────────────────────────
_CACHE: dict = {}          # (profile_id, role) -> {"m": material, "checked": float}
_LOCKS: dict = {}
_GLOBAL = threading.Lock()


def _lock_for(key) -> threading.Lock:
    with _GLOBAL:
        lk = _LOCKS.get(key)
        if lk is None:
            lk = _LOCKS[key] = threading.Lock()
        return lk


def invalidate_profile_sessions(profile_id: str) -> None:
    with _GLOBAL:
        for k in [k for k in _CACHE if k[0] == profile_id]:
            _CACHE.pop(k, None)


def _auth_hosts(rt, role) -> set:
    hosts = set()
    for f in ("login_url", "token_url"):
        if role.get(f):
            h = urlparse(_abs(base_url(rt), role[f])).hostname
            if h:
                hosts.add(h.lower())
    return hosts


def _login(rt, role) -> dict:
    fn = PROVIDERS.get(role.get("provider"))
    if fn is None:
        raise AuthError(f"unknown provider {role.get('provider')!r}")
    from tools._core import scope_guard
    with scope_guard.auth_endpoint_allowance(_auth_hosts(rt, role)):
        m = fn(rt, role)
        v = check_session(rt, role, m)
    if v is False:
        raise AuthError("logged-in indicator check failed right after login "
                        "(credentials wrong, MFA, or indicator misconfigured)")
    if v is True:
        m["verified"] = True
    return m


def get_auth(rt, role_name: Optional[str] = None, force: bool = False) -> Optional[dict]:
    """Return cached-or-fresh auth material for (profile, role). None when the
    profile defines no auth roles. Raises AuthError on login failure."""
    role = rt.role(role_name)
    if role is None:
        if role_name:
            raise AuthError(f"profile has no auth role named {role_name!r}")
        return None
    key = (rt.id, role["role"])
    with _lock_for(key):
        now = time.time()
        ent = _CACHE.get(key)
        if ent and not force and now < ent["m"]["expires_at"]:
            ind = role.get("logged_in_indicator") or {}
            interval = float(ind.get("check_interval_sec") or 300)
            if not ind or now - ent["checked"] < interval:
                return ent["m"]
            from tools._core import scope_guard
            with scope_guard.auth_endpoint_allowance(set()):
                ok = check_session(rt, role, ent["m"])
            if ok is not False:
                ent["checked"] = now
                return ent["m"]
            log.info("session for profile=%s role=%s expired; re-login", rt.id, role["role"])
        m = _login(rt, role)
        _CACHE[key] = {"m": m, "checked": time.time()}
        return m


def material_to_body(material: Optional[dict]) -> dict:
    """ScanRequest fields to inject into a scan body."""
    if not material:
        return {}
    out = {}
    if material.get("cookie"):
        out["auth_cookie"] = material["cookie"]
    if material.get("bearer"):
        out["auth_bearer"] = material["bearer"]
    if material.get("headers"):
        out["auth_headers"] = dict(material["headers"])
    return out


def public_status(material: Optional[dict]) -> dict:
    """Non-secret summary of a session for API responses / scan events."""
    if not material:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "role": material.get("role"),
        "provider": material.get("provider"),
        "has_cookie": bool(material.get("cookie")),
        "has_bearer": bool(material.get("bearer")),
        "header_names": sorted((material.get("headers") or {}).keys()),
        "verified": material.get("verified"),
        "expires_in_sec": max(0, int(material.get("expires_at", 0) - time.time())),
        "detail": material.get("detail"),
    }
