"""Org / team management API (Phase 2.1 Step 2).

Endpoints for a customer Organization to manage its team + see its audit log.
RBAC-gated via require_org_role (viewer<member<admin<owner). NOT underscore-
prefixed, so main.py autoloads it (same pattern as login.py).
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel

from tools._shared import verify_token, require_org_role
from tools.auth._db import get_db
from tools.auth._orgs import (
    get_user_org_role, get_org, list_members, add_member, change_role,
    remove_member, get_audit, write_audit, VALID_ROLES, role_rank,
)

router = APIRouter()


def _can_assign(caller_role: str, new_role: str, target_role: str = None) -> bool:
    """Tier-aware authority. An owner may grant/modify any role. Anyone else may
    only grant a role STRICTLY below their own and only act on a target STRICTLY
    below their own — so an admin can't mint/grant 'owner', can't promote anyone
    to admin, and can't demote/modify a peer admin or the owner."""
    cr = role_rank(caller_role)
    if cr >= role_rank("owner"):
        return True
    return cr > role_rank(new_role) and cr > role_rank(target_role or "")


def _can_act_on(caller_role: str, target_role: str) -> bool:
    """True if caller may remove/act on a member of `target_role` (owner may act
    on anyone; others only on someone strictly below their own tier)."""
    cr = role_rank(caller_role)
    return cr >= role_rank("owner") or cr > role_rank(target_role or "")


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    cf = request.headers.get("cf-connecting-ip", "")
    if cf:
        return cf.strip()
    return request.client.host if request.client else ""


def _org_id(payload) -> str:
    """Resolve the caller's org, verifying CURRENT membership in their claimed org
    (a removed/moved user can't keep operating on a stale org_id claim). Falls
    back to their default org."""
    sub = payload.get("sub")
    claimed = payload.get("org_id")
    oid = None
    if claimed:
        oid, _ = get_user_org_role(sub, claimed)
    if not oid:
        oid, _ = get_user_org_role(sub)
    if not oid:
        raise HTTPException(404, "No organization for this account")
    return oid


@router.get("/api/org")
def my_org(payload=Depends(verify_token)):
    oid = _org_id(payload)
    _, role = get_user_org_role(payload.get("sub"), oid)   # authoritative role
    return {"org": get_org(oid) or {}, "my_role": role}


@router.get("/api/org/members")
def members(payload=Depends(require_org_role("member"))):
    return {"members": list_members(_org_id(payload))}


class InviteReq(BaseModel):
    email: str
    role: str = "member"


@router.post("/api/org/invite")
def invite(req: InviteReq, request: Request, payload=Depends(require_org_role("admin"))):
    if req.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Allowed: {sorted(VALID_ROLES)}")
    oid = _org_id(payload)
    with get_db() as con:
        u = con.execute(
            "SELECT id, username FROM users "
            "WHERE LOWER(email)=LOWER(?) OR LOWER(username)=LOWER(?)",
            (req.email, req.email)).fetchone()
    if not u:
        # Full email-invite (send a signup link to an unregistered address) is
        # Step 2.5; for now only existing registered users can be added.
        raise HTTPException(404, "No registered user with that email/username")
    # Tier-aware authority: an admin can't invite someone as admin/owner.
    if not _can_assign(payload.get("org_role"), req.role, None):
        raise HTTPException(403, "You cannot grant a role at or above your own.")
    if not add_member(oid, u["id"], req.role, invited_by=payload.get("sub")):
        raise HTTPException(409, "User is already a member — change their role instead.")
    write_audit("user_invite", actor_id=payload.get("sub"),
                actor_name=payload.get("username"), org_id=oid,
                target=req.email, detail=f"role={req.role}", ip=_ip(request))
    return {"ok": True, "added": u["username"], "role": req.role}


class RoleReq(BaseModel):
    role: str


@router.post("/api/org/members/{user_id}/role")
def set_role(user_id: str, req: RoleReq, request: Request,
             payload=Depends(require_org_role("admin"))):
    oid = _org_id(payload)
    if req.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Allowed: {sorted(VALID_ROLES)}")
    # Tier-aware authority: an admin can't grant 'owner'/'admin' nor modify a
    # peer-or-higher (only an owner can). Look up the target's CURRENT role first.
    _, target_role = get_user_org_role(user_id, oid)
    if not target_role:
        raise HTTPException(404, "Not a member of this organization")
    if not _can_assign(payload.get("org_role"), req.role, target_role):
        raise HTTPException(403, "You cannot assign that role or modify that member.")
    if not change_role(oid, user_id, req.role):
        raise HTTPException(400, "Not a member, or the change would strand the org without an owner")
    write_audit("role_change", actor_id=payload.get("sub"),
                actor_name=payload.get("username"), org_id=oid,
                target=user_id, detail=f"role={req.role}", ip=_ip(request))
    return {"ok": True}


@router.delete("/api/org/members/{user_id}")
def remove(user_id: str, request: Request, payload=Depends(require_org_role("admin"))):
    oid = _org_id(payload)
    _, target_role = get_user_org_role(user_id, oid)
    if not target_role:
        raise HTTPException(404, "Not a member of this organization")
    # An admin can't remove a peer admin or the owner — only an owner can.
    if not _can_act_on(payload.get("org_role"), target_role):
        raise HTTPException(403, "You cannot remove that member.")
    if not remove_member(oid, user_id):
        raise HTTPException(400, "Cannot remove the last owner")
    write_audit("user_remove", actor_id=payload.get("sub"),
                actor_name=payload.get("username"), org_id=oid,
                target=user_id, ip=_ip(request))
    return {"ok": True}


@router.get("/api/org/audit")
def audit(payload=Depends(require_org_role("admin"))):
    return {"audit": get_audit(_org_id(payload))}


def register(app):
    app.include_router(router)
