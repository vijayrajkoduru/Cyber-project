"""GET /api/audit/log — read the tamper-evident audit trail.

Restricted to admin / superadmin (the live role from verify_token, which
re-validates against the DB). Supports pagination + filtering by actor/action.
Compliance asks (SOC 2 / ISO 27001) require this kind of who-did-what trail.
"""
from fastapi import APIRouter, Depends, HTTPException

from tools._shared import verify_token
from tools.auth._db import list_audit

router = APIRouter()

_ADMIN_ROLES = {"admin", "superadmin"}


@router.get("/api/audit/log")
async def audit_log(limit: int = 100, offset: int = 0,
                    actor_id: str | None = None, action: str | None = None,
                    payload=Depends(verify_token)):
    if payload.get("role") not in _ADMIN_ROLES:
        raise HTTPException(403, "Admin role required")
    return list_audit(limit=limit, offset=offset, actor_id=actor_id, action=action)


def register(app):
    app.include_router(router)
