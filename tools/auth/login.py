"""POST /api/auth/login — verify credentials, issue JWT.

Returns BOTH:
  - flat fields the React Login expects:  access_token, role, username, plan
  - the nested {user: {...}} shape for direct API users
  - 'token' alias kept for backward compatibility with curl scripts
"""
import os
import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from jose import jwt

from tools.auth._db import get_db, verify_password

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET", "")
TOKEN_TTL_HOURS = 24 * 7


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/api/auth/login")
async def auth_login(req: LoginRequest):
    with get_db() as con:
        user = con.execute(
            "SELECT id, username, email, password_hash, role, plan, status "
            "FROM users WHERE LOWER(username)=LOWER(?)",
            (req.username,),
        ).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")

    if user["status"] != "active":
        raise HTTPException(403, f"Account is {user['status']}")

    payload = {
        "sub":      user["id"],
        "username": user["username"],
        "role":     user["role"],
        "plan":     user["plan"],
        "iat":      datetime.datetime.utcnow(),
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

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
