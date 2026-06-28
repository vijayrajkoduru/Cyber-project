"""POST /api/auth/register — create user AND issue JWT (auto-login).

Returns the same shape as /api/auth/login so the frontend can call
onLogin(data.access_token, data.role, data.username, data.plan)
immediately after registration.
"""
import os
import re
import uuid
import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from jose import jwt

from tools.auth._db import get_db, hash_password

# Multi-tenant zone bootstrap — every new user gets a walled-off data dir.
# Defensive import so a bug in userzone.py never blocks registration.
try:
    from tools._core.userzone import init_zone as _init_zone
except Exception:
    _init_zone = None

import logging
_log = logging.getLogger("vulnuslab.register")

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET", "")
TOKEN_TTL_HOURS = 24 * 7


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


@router.post("/api/auth/register")
async def auth_register(req: RegisterRequest):
    if not req.username or len(req.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if not re.match(r"^[a-zA-Z0-9_.-]+$", req.username):
        raise HTTPException(400, "Username may contain only letters, numbers, _ . -")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", req.email):
        raise HTTPException(400, "Invalid email address")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    # bcrypt silently truncates at 72 bytes — reject longer passwords so two
    # different long passwords can't collide to the same hash (audit #7).
    if len(req.password.encode("utf-8")) > 72:
        raise HTTPException(400, "Password must be at most 72 bytes")

    user_id = str(uuid.uuid4())
    now_dt = datetime.datetime.utcnow()
    now = now_dt.isoformat() + "Z"
    # Trial expires 7 days after signup (audit #5).
    trial_days = int(os.getenv("TRIAL_DAYS", "7"))
    plan_expires_at = (now_dt + datetime.timedelta(days=trial_days)).isoformat() + "Z"

    with get_db() as con:
        if con.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)",
                       (req.username,)).fetchone():
            raise HTTPException(409, "Username already exists")
        if con.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)",
                       (req.email,)).fetchone():
            raise HTTPException(409, "Email already registered")
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at, plan_expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, req.username, req.email, hash_password(req.password),
             "user", "trial", "active", now, plan_expires_at),
        )

    # Provision the user's zone: /data/users/<user_id>/ with default files.
    # Failure here is logged but does NOT block registration.
    if _init_zone is not None:
        try:
            _init_zone(user_id)
            _log.info("user zone initialised for %s", user_id)
        except Exception as exc:
            _log.warning("init_zone failed for %s: %s", user_id, exc)

    payload = {
        "sub":      user_id,
        "username": req.username,
        "role":     "user",
        "plan":     "trial",
        "iat":      datetime.datetime.utcnow(),
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # Email verification + audit (both best-effort — never block signup).
    try:
        from tools.auth._db import create_email_token, record_audit
        from tools._core.email_send import send_verification_email
        record_audit("auth.register", actor_id=user_id, actor_name=req.username)
        verify_token_str = create_email_token(user_id, purpose="verify")
        send_verification_email(req.email, verify_token_str)
    except Exception as exc:
        _log.warning("post-register email/audit failed for %s: %s", user_id, exc)

    return {
        "token":        token,
        "access_token": token,
        "role":         "user",
        "username":     req.username,
        "plan":         "trial",
        "user": {
            "id":       user_id,
            "username": req.username,
            "email":    req.email,
            "role":     "user",
            "plan":     "trial",
        },
        "id":     user_id,
        "email":  req.email,
        "status": "active",
    }


def register(app):
    app.include_router(router)
