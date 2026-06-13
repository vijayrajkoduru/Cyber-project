"""Self-serve account lifecycle — /api/account/* (authenticated).

P1 customer-account table stakes: see your plan/usage, change password, change
email, export your data (DPDP/GDPR data-portability), and delete your account.
All authenticated via verify_token; sensitive actions are written to the audit
log.

NOTE on sessions: tokens are stateless JWTs (7-day TTL), so a password change
does not instantly invalidate already-issued tokens. True revocation
(tokens_valid_after / blacklist) is a separate follow-up; flagged in the
change_password response.
"""
from __future__ import annotations

import datetime
import os
import re
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import get_db, hash_password, verify_password
from tools import _quota

try:
    from tools._core.userzone import delete_zone
except Exception:  # pragma: no cover
    delete_zone = None

try:
    from tools._audit import audit_log
except Exception:  # pragma: no cover
    def audit_log(*a, **k):
        pass

router = APIRouter()

_CONSENT_DB = os.environ.get("CONSENT_DB_PATH", "/app/data/consent_audit.db")


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _ident(payload):
    return payload.get("sub") or payload.get("email") or ""


def _load(con, ident):
    return con.execute(
        "SELECT id, username, email, role, plan, status, password_hash, created_at, "
        "updated_at, subscription_expires_at, scans_used, usage_period "
        "FROM users WHERE username=? OR email=? LIMIT 1",
        (ident, ident),
    ).fetchone()


class ChangePassword(BaseModel):
    current_password: str
    new_password: str


class ChangeEmail(BaseModel):
    new_email: str
    password: str


class DeleteAccount(BaseModel):
    password: str


@router.get("/api/account/billing")
async def billing_status(payload=Depends(verify_token)):
    ident = _ident(payload)
    q = _quota.quota_status(ident)
    with get_db() as con:
        row = _load(con, ident)
    return {
        "username": payload.get("sub"),
        "plan": q.get("plan"),
        "effective_plan": q.get("effective_plan"),
        "scan_cap": q.get("cap"),
        "scans_used": q.get("used"),
        "scans_remaining": q.get("remaining"),
        "period": q.get("period"),
        "subscription_expires_at": row["subscription_expires_at"] if row else None,
        "status": row["status"] if row else None,
    }


@router.post("/api/account/password")
async def change_password(req: ChangePassword, request: Request, payload=Depends(verify_token)):
    if len(req.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    ident = _ident(payload)
    with get_db() as con:
        row = _load(con, ident)
        if not row:
            raise HTTPException(404, "User not found")
        if not verify_password(req.current_password, row["password_hash"]):
            raise HTTPException(403, "Current password is incorrect")
        con.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                    (hash_password(req.new_password), _now(), row["id"]))
    audit_log("change_password", actor=row["username"], request=request)
    return {"ok": True,
            "note": "Password updated. Existing sessions stay valid until their token expires (≤7 days)."}


@router.post("/api/account/email")
async def change_email(req: ChangeEmail, request: Request, payload=Depends(verify_token)):
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", req.new_email or ""):
        raise HTTPException(400, "Invalid email address")
    ident = _ident(payload)
    with get_db() as con:
        row = _load(con, ident)
        if not row:
            raise HTTPException(404, "User not found")
        if not verify_password(req.password, row["password_hash"]):
            raise HTTPException(403, "Password is incorrect")
        if con.execute("SELECT 1 FROM users WHERE LOWER(email)=LOWER(?) AND id<>?",
                       (req.new_email, row["id"])).fetchone():
            raise HTTPException(409, "That email is already in use")
        con.execute("UPDATE users SET email=?, updated_at=? WHERE id=?",
                    (req.new_email, _now(), row["id"]))
    audit_log("change_email", actor=row["username"], detail=req.new_email, request=request)
    return {"ok": True, "email": req.new_email}


@router.get("/api/account/export")
async def export_data(payload=Depends(verify_token)):
    """DPDP/GDPR data-portability: everything we hold on this account."""
    ident = _ident(payload)
    with get_db() as con:
        row = _load(con, ident)
    if not row:
        raise HTTPException(404, "User not found")
    account = {k: row[k] for k in row.keys() if k != "password_hash"}
    scans = []
    try:
        c = sqlite3.connect(f"file:{_CONSENT_DB}?mode=ro", uri=True)
        c.row_factory = sqlite3.Row
        key = account.get("email") or account.get("username")
        scans = [dict(r) for r in c.execute(
            "SELECT ts, target, module FROM consent_log WHERE user_email=? ORDER BY ts DESC",
            (key,)).fetchall()]
        c.close()
    except Exception:
        pass
    return {"account": account, "scan_history": scans, "exported_at": _now()}


@router.post("/api/account/delete")
async def delete_account(req: DeleteAccount, request: Request, payload=Depends(verify_token)):
    ident = _ident(payload)
    if payload.get("role") in ("admin", "superadmin") or str(ident).upper() == "ADMIN":
        raise HTTPException(403, "Admin accounts cannot self-delete (use the admin API)")
    with get_db() as con:
        row = _load(con, ident)
        if not row:
            raise HTTPException(404, "User not found")
        if not verify_password(req.password, row["password_hash"]):
            raise HTTPException(403, "Password is incorrect")
        uid, uname = row["id"], row["username"]
        con.execute("DELETE FROM users WHERE id=?", (uid,))
    if delete_zone:
        try:
            delete_zone(uid)
        except Exception:
            pass
    audit_log("delete_account", actor=uname, request=request)
    return {"ok": True, "deleted": uname}


def register(app):
    app.include_router(router)
