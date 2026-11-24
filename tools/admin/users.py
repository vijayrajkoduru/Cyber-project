"""Admin User Management — /api/admin/users/* — admin-only."""
import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import get_db, is_plan_demotion, forget_cached_user

router = APIRouter()


def _is_superadmin(con, username: str) -> bool:
    row = con.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    return bool(row) and row["role"] == "superadmin"


def verify_admin_or_super(payload=Depends(verify_token)):
    if not payload.get("_role_verified"):
        raise HTTPException(403, "Account state could not be verified; admin access denied")
    if payload.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin role required")
    return payload


def _set_plan(username: str, plan: str, expires) -> None:
    """Write plan + expiry; on a DEMOTION (lower-ranked plan) also bump
    token_version so every outstanding session is revoked (TOKEN-REVOKE-V1).
    Upgrades / same-plan extensions leave sessions alone. 404 if missing."""
    with get_db() as con:
        cur = con.execute("SELECT id, plan FROM users WHERE username=?",
                          (username,)).fetchone()
        if not cur:
            raise HTTPException(404, f"User '{username}' not found")
        bump = 1 if is_plan_demotion(cur["plan"], plan) else 0
        con.execute(
            "UPDATE users SET plan=?, plan_expires_at=?, token_version = token_version + ? "
            "WHERE id=?", (plan, expires, bump, cur["id"]))
    forget_cached_user(cur["id"])


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
    with get_db() as con:
        if _is_superadmin(con, username):
            raise HTTPException(403, "Cannot suspend a superadmin account")
        # TOKEN-REVOKE-V1: also bump token_version so re-activating the
        # account later does NOT revive the tokens issued before suspension.
        row = con.execute(
            "UPDATE users SET status='suspended', token_version = token_version + 1 "
            "WHERE username=? RETURNING id", (username,)).fetchone()
        if not row:
            raise HTTPException(404, f"User '{username}' not found")
    forget_cached_user(row["id"])
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
    # Trial gets a 7-day window; paid plans don't expire until explicitly
    # changed/extended, so clear any inherited expiry (audit #5).
    if req.plan == "trial":
        expires = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat() + "Z"
    else:
        expires = None
    _set_plan(username, req.plan, expires)
    return {"ok": True, "username": username, "plan": req.plan, "plan_expires_at": expires}


@router.post("/api/admin/users/{username}/extend")
async def extend_plan(username: str, req: ExtendRequest, _=Depends(verify_admin_or_super)):
    if req.days < 0 or req.days > 3650:
        raise HTTPException(400, "days must be between 0 and 3650")
    # Grant access for `days` from now and persist it (audit #5) — previously
    # the days were accepted but never written, so plans never actually lapsed.
    expires = (datetime.datetime.utcnow() + datetime.timedelta(days=req.days)).isoformat() + "Z"
    _set_plan(username, req.plan, expires)
    return {"ok": True, "username": username, "extended_days": req.days,
            "plan": req.plan, "plan_expires_at": expires}


@router.delete("/api/admin/users/{username}")
async def delete_user(username: str, _=Depends(verify_admin_or_super)):
    with get_db() as con:
        if _is_superadmin(con, username):
            raise HTTPException(403, "Cannot delete a superadmin account")
        row = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            raise HTTPException(404, f"User '{username}' not found")
        user_id = row["id"]
        # Deleting the row already makes verify_token 401 ("Account no longer
        # exists"); drop the cached row so it is immediate in this worker.
        con.execute("DELETE FROM users WHERE username=?", (username,))
    forget_cached_user(user_id)
    try:
        from tools._core.userzone import delete_zone
        delete_zone(user_id)
    except Exception:
        pass
    return {"ok": True, "username": username, "deleted": True}


def register(app):
    app.include_router(router)
