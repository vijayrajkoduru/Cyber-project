"""POST /api/auth/login — verify credentials, issue JWT.

Returns BOTH:
  - flat fields the React Login expects:  access_token, role, username, plan
  - the nested {user: {...}} shape for direct API users
  - 'token' alias kept for backward compatibility with curl scripts
"""
import os
import time
import datetime
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from jose import jwt

from tools.auth._db import get_db, verify_password, record_audit

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
async def auth_login(req: LoginRequest, request: Request):
    key = _throttle_key(request, req.username)
    if not _login_allowed(key):
        raise HTTPException(429, "Too many login attempts; please wait and try again.")
    _record_attempt(key)

    with get_db() as con:
        user = con.execute(
            "SELECT id, username, email, password_hash, role, plan, status, "
            "mfa_enabled, mfa_secret "
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

    payload = {
        "sub":      user["id"],
        "username": user["username"],
        "role":     user["role"],
        "plan":     user["plan"],
        "iat":      datetime.datetime.utcnow(),
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Ensure this user has a zone (idempotent — no-op if it already exists).
    if _init_zone is not None:
        try:
            _init_zone(user["id"])
        except Exception as exc:
            _log.warning("zone lazy-init failed for %s: %s", user["id"], exc)

    return {
        "token":        token,
        "access_token": token,
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


def register(app):
    app.include_router(router)
