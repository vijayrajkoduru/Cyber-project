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

    user_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat() + "Z"

    with get_db() as con:
        if con.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)",
                       (req.username,)).fetchone():
            raise HTTPException(409, "Username already exists")
        if con.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)",
                       (req.email,)).fetchone():
            raise HTTPException(409, "Email already registered")
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, plan, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, req.username, req.email, hash_password(req.password),
             "user", "trial", "active", now),
        )

    payload = {
        "sub":      user_id,
        "username": req.username,
        "role":     "user",
        "plan":     "trial",
        "iat":      datetime.datetime.utcnow(),
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

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
