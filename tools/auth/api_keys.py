"""Programmatic API keys — let customers authenticate automation without a
password/JWT. Keys are shown once at creation and stored only as a bcrypt hash.

  POST   /api/auth/api-keys        create a key (returns the secret ONCE)
  GET    /api/auth/api-keys        list this user's keys (metadata only)
  DELETE /api/auth/api-keys/{id}   revoke a key

Use the key as a normal bearer token: `Authorization: Bearer vlk_...`.
tools/_shared.verify_token accepts it (see the api-key branch there).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from tools._shared import verify_token
from tools.auth._db import (create_api_key, list_api_keys, revoke_api_key,
                            record_audit)

router = APIRouter()


class CreateKeyRequest(BaseModel):
    name: str = "api-key"


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else (
        request.client.host if request.client else "?")


@router.post("/api/auth/api-keys")
async def create_key(req: CreateKeyRequest, request: Request, payload=Depends(verify_token)):
    uid = payload.get("sub")
    name = (req.name or "api-key")[:64]
    secret, meta = create_api_key(uid, name)
    record_audit("api_key.create", actor_id=uid, actor_name=payload.get("username"),
                 target=meta["id"], ip=_client_ip(request), detail=name)
    # secret is returned exactly once; the client must store it now.
    return {"secret": secret, "key": meta,
            "warning": "Store this secret now — it will not be shown again."}


@router.get("/api/auth/api-keys")
async def list_keys(payload=Depends(verify_token)):
    return {"keys": list_api_keys(payload.get("sub"))}


@router.delete("/api/auth/api-keys/{key_id}")
async def delete_key(key_id: str, request: Request, payload=Depends(verify_token)):
    uid = payload.get("sub")
    if not revoke_api_key(uid, key_id):
        raise HTTPException(404, "Key not found or already revoked")
    record_audit("api_key.revoke", actor_id=uid, actor_name=payload.get("username"),
                 target=key_id, ip=_client_ip(request))
    return {"status": "revoked", "id": key_id}


def register(app):
    app.include_router(router)
