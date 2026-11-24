"""POST /api/auth/login — verify credentials, issue JWT.

Returns BOTH:
  - flat fields the React Login expects:  access_token, role, username, plan
  - the nested {user: {...}} shape for direct API users
  - 'token' alias kept for backward compatibility with curl scripts
"""
import os
import time
import datetime
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from jose import jwt

from tools.auth._db import (get_db, verify_password, record_audit, new_token_claims,
                            revoke_user_sessions)
from tools.auth._session_cookie import set_session_cookies, clear_session_cookies

# Lazy zone init — covers existing users who registered before USERZONE shipped.
try:
    from tools._core.userzone import init_zone as _init_zone
except Exception:
    _init_zone = None

import logging
_log = logging.getLogger("vulnuslab.login")

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET", "")
TOKEN_TTL_HOURS = 24 * 7

# ── Brute-force throttle (audit #8): in-process sliding window ───────
# Limits login attempts per (client IP + username). In-process is fine for
# a single instance; move to Redis if/when the API scales horizontally.
_LOGIN_WINDOW_SEC = int(os.getenv("LOGIN_THROTTLE_WINDOW", "300"))
_LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_THROTTLE_MAX", "10"))
_login_attempts: dict[str, list[float]] = {}


def _throttle_key(request: Request, username: str) -> str:
    ip = request.client.host if request and request.client else "?"
    return f"{ip}:{username.lower()}"


def _login_allowed(key: str) -> bool:
    now = time.time()
    hits = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW_SEC]
    _login_attempts[key] = hits
    return len(hits) < _LOGIN_MAX_ATTEMPTS


def _record_attempt(key: str):
    _login_attempts.setdefault(key, []).append(time.time())


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


@router.post("/api/auth/login")
async def auth_login(req: LoginRequest, request: Request, response: Response):
    key = _throttle_key(request, req.username)
    if not _login_allowed(key):
        raise HTTPException(429, "Too many login attempts; please wait and try again.")
    _record_attempt(key)

    with get_db() as con:
        user = con.execute(
            "SELECT id, username, email, password_hash, role, plan, status, "
            "mfa_enabled, mfa_secret, token_version "
            "FROM users WHERE LOWER(username)=LOWER(?)",
            (req.username,),
        ).fetchone()

    _ip = request.client.host if request and request.client else None

    if not user or not verify_password(req.password, user["password_hash"]):
        record_audit("auth.login_failed", actor_name=req.username, ip=_ip,
                     status="fail", detail="invalid credentials")
        raise HTTPException(401, "Invalid username or password")

    if user["status"] != "active":
        record_audit("auth.login_blocked", actor_id=user["id"],
                     actor_name=user["username"], ip=_ip, status="fail",
                     detail=f"status={user['status']}")
        raise HTTPException(403, f"Account is {user['status']}")

    # MFA gate: if enabled, a valid TOTP code is required to complete login.
    if user.get("mfa_enabled"):
        if not req.mfa_code:
            record_audit("auth.mfa_required", actor_id=user["id"],
                         actor_name=user["username"], ip=_ip, status="pending")
            raise HTTPException(401, "MFA code required", headers={"X-MFA-Required": "1"})
        try:
            import pyotp
            valid = pyotp.TOTP(user["mfa_secret"]).verify(req.mfa_code.strip(), valid_window=1)
        except ImportError:
            _log.error("pyotp not installed but user %s has MFA enabled", user["id"])
            raise HTTPException(500, "MFA verification unavailable")
        if not valid:
            record_audit("auth.mfa_failed", actor_id=user["id"],
                         actor_name=user["username"], ip=_ip, status="fail")
            raise HTTPException(401, "Invalid MFA code")

    record_audit("auth.login", actor_id=user["id"], actor_name=user["username"], ip=_ip)

    # TOKEN-REVOKE-V1: sub/ver/jti/iat — `ver` ties the token to the user's
    # current token_version so a later bump revokes it server-side.
    payload = new_token_claims(user["id"], user.get("token_version") or 0)
    payload.update({
        "username": user["username"],
        "role":     user["role"],
        "plan":     user["plan"],
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    })
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Ensure this user has a zone (idempotent — no-op if it already exists).
    if _init_zone is not None:
        try:
            _init_zone(user["id"])
        except Exception as exc:
            _log.warning("zone lazy-init failed for %s: %s", user["id"], exc)

    # SESSION-COOKIE-V1: browsers get the JWT only as an HttpOnly cookie.
    csrf = set_session_cookies(response, token, request)
    body = {
        "token":        token,
        "access_token": token,
        "csrf_token":   csrf,
        "session":      "cookie",
        "role":         user["role"],
        "username":     user["username"],
        "plan":         user["plan"],
        "user": {
            "id":       user["id"],
            "username": user["username"],
            "email":    user["email"],
            "role":     user["role"],
            "plan":     user["plan"],
        },
    }
    # The web SPA sends X-VL-Session: cookie — it must never see the raw JWT
    # (keeps it out of JS reach entirely). API/CLI clients still receive it.
    if (request.headers.get("x-vl-session") or "").lower() == "cookie":
        body.pop("token", None)
        body.pop("access_token", None)
    return body


@router.post("/api/auth/logout")
async def auth_logout(request: Request, response: Response):
    """Clear the browser session cookies AND revoke the session server-side
    (TOKEN-REVOKE-V1): if the presented JWT (cookie or Bearer) is valid and
    still current, bump the user's token_version, which invalidates EVERY
    outstanding token for that user ("log out everywhere"). The bump is a
    compare-and-swap on the token's own `ver`, so an already-revoked token
    cannot re-trigger it. Idempotent; always 200 so a stale/garbage cookie
    can still be cleared."""
    clear_session_cookies(response, request)
    revoked = False
    try:
        from tools._shared import JWT_SECRET as _sec
        from tools.auth._session_cookie import SESSION_COOKIE, real_bearer
        from jose import jwt as _j
        # main.py's cookie middleware turns the vl_session cookie into a
        # Bearer header, so check the header first, then the raw cookie.
        raw = real_bearer(request.headers.get("authorization")) \
            or request.cookies.get(SESSION_COOKIE)
        if raw:
            p = _j.decode(raw, _sec, algorithms=["HS256"])
            sub = p.get("sub")
            _ip = request.client.host if request and request.client else None
            if sub:
                try:
                    ver = int(p.get("ver") or 0)
                    revoked = revoke_user_sessions(sub, expected_version=ver) is not None
                except Exception as exc:
                    _log.warning("logout revocation failed for %s: %s", sub, exc)
            record_audit("auth.logout", actor_id=sub, actor_name=p.get("username"), ip=_ip,
                         detail="sessions revoked" if revoked else "cookie cleared")
    except Exception:
        pass
    return {"ok": True, "revoked": revoked}


def register(app):
    app.include_router(router)
