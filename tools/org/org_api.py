"""Organizations + role-based access control (enterprise multi-tenancy).

  POST   /api/orgs                      create an org (creator = owner)
  GET    /api/orgs                      list orgs I belong to (+ my role)
  GET    /api/orgs/{id}/members         list members        (member+)
  POST   /api/orgs/{id}/members         add/invite by email (admin+)
  PATCH  /api/orgs/{id}/members/{uid}   change a member role (admin+)
  DELETE /api/orgs/{id}/members/{uid}   remove a member     (admin+)

Roles: member < admin < owner. Authorization is resolved per-request from the
org_members table (source of truth), so role changes take effect immediately.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import (create_org, list_user_orgs, get_org, get_member_role,
                            has_org_role, list_org_members, add_org_member,
                            set_member_role, remove_org_member, find_user_by_email,
                            ORG_ROLES, record_audit)

router = APIRouter()


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else (request.client.host if request.client else "?")


def _require_role(org_id: str, uid: str, min_role: str):
    if not get_org(org_id):
        raise HTTPException(404, "Organization not found")
    if not has_org_role(org_id, uid, min_role):
        raise HTTPException(403, f"Requires org role: {min_role}+")


class CreateOrgRequest(BaseModel):
    name: str


class AddMemberRequest(BaseModel):
    email: str
    role: str = "member"


class RoleRequest(BaseModel):
    role: str


@router.post("/api/orgs")
async def create_organization(req: CreateOrgRequest, request: Request, payload=Depends(verify_token)):
    name = (req.name or "").strip()
    if len(name) < 2:
        raise HTTPException(400, "Org name must be at least 2 characters")
    org = create_org(name, payload.get("sub"))
    record_audit("org.create", actor_id=payload.get("sub"),
                 actor_name=payload.get("username"), target=org["id"], ip=_ip(request), detail=name)
    return org


@router.get("/api/orgs")
async def my_orgs(payload=Depends(verify_token)):
    return {"orgs": list_user_orgs(payload.get("sub"))}


@router.get("/api/orgs/{org_id}/members")
async def org_members(org_id: str, payload=Depends(verify_token)):
    _require_role(org_id, payload.get("sub"), "member")
    return {"members": list_org_members(org_id)}


@router.post("/api/orgs/{org_id}/members")
async def add_member(org_id: str, req: AddMemberRequest, request: Request, payload=Depends(verify_token)):
    _require_role(org_id, payload.get("sub"), "admin")
    if req.role not in ORG_ROLES or req.role == "owner":
        raise HTTPException(400, "Role must be 'member' or 'admin'")
    user = find_user_by_email(req.email)
    if not user:
        raise HTTPException(404, "No user with that email (they must register first)")
    add_org_member(org_id, user["id"], req.role)
    record_audit("org.member_add", actor_id=payload.get("sub"),
                 actor_name=payload.get("username"), target=f"{org_id}/{user['id']}",
                 ip=_ip(request), detail=req.role)
    return {"status": "added", "user_id": user["id"], "role": req.role}


@router.patch("/api/orgs/{org_id}/members/{user_id}")
async def change_role(org_id: str, user_id: str, req: RoleRequest, request: Request, payload=Depends(verify_token)):
    _require_role(org_id, payload.get("sub"), "admin")
    if req.role not in ORG_ROLES:
        raise HTTPException(400, f"Invalid role; one of {list(ORG_ROLES)}")
    org = get_org(org_id)
    if org["owner_id"] == user_id:
        raise HTTPException(409, "Cannot change the owner's role (transfer ownership instead)")
    if not set_member_role(org_id, user_id, req.role):
        raise HTTPException(404, "Member not found")
    record_audit("org.role_change", actor_id=payload.get("sub"),
                 actor_name=payload.get("username"), target=f"{org_id}/{user_id}",
                 ip=_ip(request), detail=req.role)
    return {"status": "updated", "user_id": user_id, "role": req.role}


@router.delete("/api/orgs/{org_id}/members/{user_id}")
async def remove_member(org_id: str, user_id: str, request: Request, payload=Depends(verify_token)):
    _require_role(org_id, payload.get("sub"), "admin")
    if not remove_org_member(org_id, user_id):
        raise HTTPException(409, "Cannot remove (member not found or is the owner)")
    record_audit("org.member_remove", actor_id=payload.get("sub"),
                 actor_name=payload.get("username"), target=f"{org_id}/{user_id}", ip=_ip(request))
    return {"status": "removed", "user_id": user_id}


def register(app):
    app.include_router(router)
