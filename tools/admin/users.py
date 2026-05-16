"""Admin User Management — /api/admin/users/* — admin-only."""
import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import get_db

router = APIRouter()


def verify_admin_or_super(payload=Depends(verify_token)):
    if payload.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin role required")
    return payload


class PlanRequest(BaseModel):
    plan: str


class ExtendRequest(BaseModel):
    days: int
    plan: str = "trial"


@router.get("/api/admin/users")
async def list_users(_=Depends(verify_admin_or_super)):
    with get_db() as con:
        rows = con.execute(
            "SELECT id, username, email, role, plan, status, created_at "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
        users = [{
            "id": r["id"], "username": r["username"], "email": r["email"],
            "role": r["role"], "plan": r["plan"], "status": r["status"],
            "created_at": r["created_at"],
        } for r in rows]
    return {"users": users, "total": len(users)}


@router.post("/api/admin/users/{username}/suspend")
async def suspend_user(username: str, _=Depends(verify_admin_or_super)):
    if username.upper() == "ADMIN":
        raise HTTPException(403, "Cannot suspend the ADMIN account")
    with get_db() as con:
        result = con.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
        if result.rowcount == 0:
            raise HTTPException(404, f"User '{username}' not found")
    return {"ok": True, "username": username, "status": "suspended"}


@router.post("/api/admin/users/{username}/activate")
async def activate_user(username: str, _=Depends(verify_admin_or_super)):
    with get_db() as con:
        result = con.execute("UPDATE users SET status='active' WHERE username=?", (username,))
        if result.rowcount == 0:
            raise HTTPException(404, f"User '{username}' not found")
    return {"ok": True, "username": username, "status": "active"}


@router.post("/api/admin/users/{username}/plan")
async def change_plan(username: str, req: PlanRequest, _=Depends(verify_admin_or_super)):
    valid = {"trial", "pro", "enterprise", "superadmin"}
    if req.plan not in valid:
        raise HTTPException(400, f"Invalid plan. Must be one of: {sorted(valid)}")
    with get_db() as con:
        result = con.execute("UPDATE users SET plan=? WHERE username=?", (req.plan, username))
        if result.rowcount == 0:
            raise HTTPException(404, f"User '{username}' not found")
    return {"ok": True, "username": username, "plan": req.plan}


@router.post("/api/admin/users/{username}/extend")
async def extend_plan(username: str, req: ExtendRequest, _=Depends(verify_admin_or_super)):
    if req.days < 0 or req.days > 3650:
        raise HTTPException(400, "days must be between 0 and 3650")
    with get_db() as con:
        result = con.execute("UPDATE users SET plan=? WHERE username=?", (req.plan, username))
        if result.rowcount == 0:
            raise HTTPException(404, f"User '{username}' not found")
    return {"ok": True, "username": username, "extended_days": req.days, "plan": req.plan}


@router.delete("/api/admin/users/{username}")
async def delete_user(username: str, _=Depends(verify_admin_or_super)):
    if username.upper() == "ADMIN":
        raise HTTPException(403, "Cannot delete the ADMIN account")
    with get_db() as con:
        row = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            raise HTTPException(404, f"User '{username}' not found")
        user_id = row["id"]
        con.execute("DELETE FROM users WHERE username=?", (username,))
    try:
        from tools._core.userzone import delete_zone
        delete_zone(user_id)
    except Exception:
        pass
    return {"ok": True, "username": username, "deleted": True}


def register(app):
    app.include_router(router)
