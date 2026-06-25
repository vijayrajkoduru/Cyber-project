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
    remove_member, get_audit, count_audit, purge_old_audit, write_audit,
    VALID_ROLES, role_rank,
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
def audit(limit: int = 100, offset: int = 0, payload=Depends(require_org_role("admin"))):
    oid = _org_id(payload)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    return {"audit": get_audit(oid, limit, offset), "total": count_audit(oid),
            "limit": limit, "offset": offset}


# ─── API keys (Phase 2.4) — issue/list/revoke org-scoped keys ───────────────
class KeyReq(BaseModel):
    name: str = "API key"
    role: str = "member"


@router.post("/api/org/keys")
def create_key(req: KeyReq, request: Request, payload=Depends(require_org_role("admin"))):
    oid = _org_id(payload)
    if req.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Allowed: {sorted(VALID_ROLES)}")
    # A key can't carry more authority than the admin minting it.
    if not _can_assign(payload.get("org_role"), req.role, None):
        raise HTTPException(403, "You cannot issue a key with a role at or above your own.")
    from tools.auth._apikeys import create_api_key
    kid, plaintext, prefix = create_api_key(oid, req.name, req.role, payload.get("sub"))
    write_audit("api_key_create", actor_id=payload.get("sub"),
                actor_name=payload.get("username"), org_id=oid,
                target=(req.name or "")[:80], detail=f"role={req.role}", ip=_ip(request))
    return {"ok": True, "id": kid, "api_key": plaintext, "prefix": prefix,
            "warning": "Store this key now — it is shown only once and cannot be retrieved again."}


@router.get("/api/org/keys")
def list_keys(payload=Depends(require_org_role("admin"))):
    from tools.auth._apikeys import list_api_keys
    return {"keys": list_api_keys(_org_id(payload))}


@router.delete("/api/org/keys/{key_id}")
def revoke_key(key_id: str, request: Request, payload=Depends(require_org_role("admin"))):
    oid = _org_id(payload)
    from tools.auth._apikeys import revoke_api_key
    if not revoke_api_key(oid, key_id):
        raise HTTPException(404, "API key not found")
    write_audit("api_key_revoke", actor_id=payload.get("sub"),
                actor_name=payload.get("username"), org_id=oid,
                target=key_id, ip=_ip(request))
    return {"ok": True}


_purge_started = False


def register(app):
    app.include_router(router)

    @app.on_event("startup")
    async def _start_audit_purge():
        # Enforce audit retention (purge_old_audit was previously dead code, so the
        # log grew unbounded). Runs once on boot, then daily. Idempotent across
        # workers (DELETE WHERE ts < cutoff). Retention is env-tunable.
        global _purge_started
        if _purge_started:
            return
        _purge_started = True
        import asyncio
        import os

        async def _loop():
            try:
                days = int(os.getenv("VL_AUDIT_RETENTION_DAYS", "365"))
            except Exception:
                days = 365
            while True:
                try:
                    purge_old_audit(days=days)
                except Exception:
                    pass
                await asyncio.sleep(86400)  # daily

        asyncio.create_task(_loop())
