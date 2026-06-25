"""OpenID Connect SSO (Phase 2.2) — works with Google / Okta / Azure AD / Auth0.

OFF BY DEFAULT. It only activates when OIDC_ISSUER + OIDC_CLIENT_ID +
OIDC_CLIENT_SECRET + OIDC_REDIRECT_URI (+ JWT_SECRET) are all set, so it can
never affect the existing username/password login.

Flow: standard OIDC authorization-code.
  /api/auth/sso/login    -> 307 to the IdP authorize endpoint (state+nonce in a
                            short-lived signed cookie, so it survives across the
                            4 uvicorn workers).
  /api/auth/sso/callback -> validate state, exchange code at the token endpoint,
                            VALIDATE the id_token (RS256 signature via the IdP's
                            JWKS, plus iss/aud/exp/nonce), JIT-provision a user +
                            personal org, mint the SAME JWT a password login does,
                            and 307 back to the SPA with the token in the URL
                            fragment (#sso_token=...), which the SPA stores.
"""
import os
import time
import uuid
import datetime
import secrets
from urllib.parse import urlencode

import requests
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse
from jose import jwt as _jwt

from tools.auth._db import get_db, hash_password

router = APIRouter()

OIDC_ISSUER = os.getenv("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "")
OIDC_NAME = os.getenv("OIDC_NAME", "SSO")
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid email profile")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://app.vulnuslab.com").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "")
TOKEN_TTL_HOURS = 24 * 7
_STATE_COOKIE = "vl_sso_state"


def _enabled() -> bool:
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
                and OIDC_REDIRECT_URI and JWT_SECRET)


# ── IdP discovery + JWKS (cached) ────────────────────────────────────
_disc_cache = {}
_jwks_cache = {}


def _discovery():
    if _disc_cache.get("exp", 0) > time.time():
        return _disc_cache["doc"]
    r = requests.get(OIDC_ISSUER + "/.well-known/openid-configuration", timeout=10)
    r.raise_for_status()
    doc = r.json()
    _disc_cache.update(doc=doc, exp=time.time() + 3600)
    return doc


def _jwks():
    uri = _discovery()["jwks_uri"]
    if _jwks_cache.get("uri") == uri and _jwks_cache.get("exp", 0) > time.time():
        return _jwks_cache["keys"]
    r = requests.get(uri, timeout=10)
    r.raise_for_status()
    keys = r.json().get("keys", [])
    _jwks_cache.update(uri=uri, keys=keys, exp=time.time() + 3600)
    return keys


def _key_for(kid):
    for k in _jwks():
        if k.get("kid") == kid:
            return k
    _jwks_cache["exp"] = 0   # force one refresh in case the IdP rotated keys
    for k in _jwks():
        if k.get("kid") == kid:
            return k
    return None


def _validate_id_token(id_token: str, nonce: str) -> dict:
    """Verify signature (JWKS/RS256) + iss + aud + exp, then the nonce. Any
    failure raises — a token that doesn't fully validate is never trusted."""
    try:
        hdr = _jwt.get_unverified_header(id_token)
    except Exception:
        raise HTTPException(400, "malformed id_token")
    key = _key_for(hdr.get("kid"))
    if not key:
        raise HTTPException(400, "no matching IdP signing key")
    alg = hdr.get("alg", "RS256")
    if alg not in ("RS256", "RS384", "RS512"):
        raise HTTPException(400, f"unsupported id_token alg {alg}")
    try:
        claims = _jwt.decode(
            id_token, key, algorithms=[alg],
            audience=OIDC_CLIENT_ID, issuer=OIDC_ISSUER,
            options={"verify_at_hash": False})
    except Exception as e:
        raise HTTPException(400, f"id_token validation failed: {e}")
    if nonce and claims.get("nonce") != nonce:
        raise HTTPException(400, "nonce mismatch")
    return claims


def _provision_and_issue(email: str, name: str) -> str:
    """Find or JIT-create the user for this verified email, ensure their org,
    and mint the standard app JWT (identical shape to a password login)."""
    with get_db() as con:
        u = con.execute(
            "SELECT id, username, role, plan, status FROM users WHERE LOWER(email)=LOWER(?)",
            (email,)).fetchone()
        if u and u["status"] != "active":
            raise HTTPException(403, f"Account is {u['status']}")
        if u:
            user_id, username, role, plan = u["id"], u["username"], u["role"], u["plan"]
        else:
            user_id = str(uuid.uuid4())
            username = (email.split("@")[0] or "user") + "-" + user_id[:4]
            now = datetime.datetime.utcnow().isoformat() + "Z"
            con.execute(
                "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (user_id, username, email, hash_password(secrets.token_urlsafe(32)),
                 "user", "trial", "active", now))
            role, plan = "user", "trial"

    org_id = org_role = None
    try:
        from tools.auth._orgs import get_or_create_personal_org, get_user_org_role
        get_or_create_personal_org(user_id, username, plan)
        org_id, org_role = get_user_org_role(user_id)
    except Exception:
        pass

    payload = {
        "sub": user_id, "username": username, "role": role, "plan": plan,
        "org_id": org_id, "org_role": org_role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    token = _jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    try:
        from tools.auth._orgs import write_audit
        write_audit("login_sso", actor_id=user_id, actor_name=username, org_id=org_id)
    except Exception:
        pass
    return token


# ── Endpoints ────────────────────────────────────────────────────────
@router.get("/api/auth/sso/status")
def sso_status():
    """The SPA calls this to decide whether to show the SSO button."""
    return {"enabled": _enabled(), "name": OIDC_NAME if _enabled() else None}


@router.get("/api/auth/sso/login")
def sso_login():
    if not _enabled():
        raise HTTPException(404, "SSO is not configured")
    doc = _discovery()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    url = doc["authorization_endpoint"] + "?" + urlencode({
        "response_type": "code", "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI, "scope": OIDC_SCOPES,
        "state": state, "nonce": nonce})
    cookie = _jwt.encode(
        {"state": state, "nonce": nonce,
         "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
        JWT_SECRET, algorithm="HS256")
    resp = RedirectResponse(url, status_code=307)
    resp.set_cookie(_STATE_COOKIE, cookie, max_age=600, httponly=True,
                    secure=True, samesite="lax")
    return resp


@router.get("/api/auth/sso/callback")
def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if not _enabled():
        raise HTTPException(404, "SSO is not configured")
    if error:
        return RedirectResponse(FRONTEND_URL + "/#sso_error=" + error, status_code=307)
    if not code or not state:
        raise HTTPException(400, "missing code/state")
    raw = request.cookies.get(_STATE_COOKIE, "")
    try:
        st = _jwt.decode(raw, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(400, "invalid or expired SSO state")
    if not secrets.compare_digest(str(st.get("state", "")), str(state)):
        raise HTTPException(400, "state mismatch")
    doc = _discovery()
    tr = requests.post(doc["token_endpoint"], data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": OIDC_REDIRECT_URI,
        "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET},
        timeout=15)
    if tr.status_code != 200:
        raise HTTPException(400, "token exchange failed")
    id_token = tr.json().get("id_token")
    if not id_token:
        raise HTTPException(400, "IdP returned no id_token")
    claims = _validate_id_token(id_token, st.get("nonce", ""))
    email = (claims.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(400, "id_token has no email claim")
    if claims.get("email_verified") is False:
        raise HTTPException(403, "email not verified by the identity provider")
    token = _provision_and_issue(email, claims.get("name") or email)
    resp = RedirectResponse(FRONTEND_URL + "/#sso_token=" + token, status_code=307)
    resp.delete_cookie(_STATE_COOKIE)
    return resp


def register(app):
    app.include_router(router)
