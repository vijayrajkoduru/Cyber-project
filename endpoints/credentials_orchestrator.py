"""credentials module orchestrator - Customer Credential Vault REST API.

Exposes endpoints for the encrypted vault that stores customer-supplied
credentials (AWS keys, AD domain users, K8s kubeconfigs, OAuth tokens,
etc.). These are the per-customer authentication artifacts that the AD /
Cloud / SSPM / Auth Attacks / etc. modules need to actually scan customer
infrastructure.

ALL endpoints require JWT auth via verify_token. The vault is scoped per-
user_id (JWT sub). A user can only see/use/modify their own credentials.
Even an admin cannot decrypt another user's credentials without the per-
user HKDF-derived subkey + the user's user_id used as AAD - the system
is designed so a single admin compromise does NOT yield all customer creds.

Endpoints:
  GET    /api/credentials                   - List all (masked metadata)
  GET    /api/credentials/types             - List supported credential types
  POST   /api/credentials                   - Create new credential set
  GET    /api/credentials/{id}              - Get one (masked metadata only)
  PUT    /api/credentials/{id}              - Update name / fields
  DELETE /api/credentials/{id}              - Delete + remove from audit log
  GET    /api/credentials/{id}/usage        - Get usage audit log for one cred
  GET    /api/credentials/usage             - Get usage audit log for all creds

Security notes for callers:
- POST + PUT accept plaintext fields in the request body. TLS in transit
  is REQUIRED (already enforced via nginx on app.vulnuslab.com).
- The DECRYPT path (use_credential) is NOT exposed as an HTTP endpoint.
  Module probes call _vault.use_credential() directly with the JWT sub.
  This means decrypted plaintext never leaves the backend process.
- Audit log: every decrypt is logged with cred_id + scan_id + used_for.
"""
from __future__ import annotations

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token
from tools.credentials._vault import (
    SUPPORTED_TYPES,
    list_credentials,
    get_credential_metadata,
    create_credential,
    update_credential,
    delete_credential,
    get_usage_log,
)

router = APIRouter()


def _user_id_from_payload(payload: dict) -> str:
    uid = payload.get("sub")
    if not uid:
        raise HTTPException(401, "JWT missing sub claim")
    return uid


# ──────────────────────────────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────────────────────────────


class CreateCredentialRequest(BaseModel):
    name: str
    cred_type: str
    fields: Dict[str, Any]


class UpdateCredentialRequest(BaseModel):
    name: Optional[str] = None
    fields: Optional[Dict[str, Any]] = None


# ──────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────


@router.get("/api/credentials/types")
async def credentials_types(_=Depends(verify_token)):
    """Return all supported credential types + their field schemas.
    Used by the frontend to render the 'Add Credential' wizard."""
    return {"types": SUPPORTED_TYPES}


@router.get("/api/credentials")
async def credentials_list(payload=Depends(verify_token)):
    """List all credential sets for the current user (masked, never decrypted)."""
    user_id = _user_id_from_payload(payload)
    rows = list_credentials(user_id)
    return {"credentials": rows, "count": len(rows)}


@router.post("/api/credentials")
async def credentials_create(req: CreateCredentialRequest, payload=Depends(verify_token)):
    """Create a new credential set. Body must include name + cred_type +
    fields dict matching the schema of cred_type."""
    user_id = _user_id_from_payload(payload)
    if not req.name or len(req.name) > 80:
        raise HTTPException(400, "name must be 1-80 chars")
    if req.cred_type not in SUPPORTED_TYPES:
        raise HTTPException(400, f"unsupported cred_type: {req.cred_type}")
    try:
        new_id = create_credential(user_id, req.name, req.cred_type, req.fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
    meta = get_credential_metadata(user_id, new_id)
    return {"created": True, "credential": meta}


@router.get("/api/credentials/{cred_id}")
async def credentials_get(cred_id: str, payload=Depends(verify_token)):
    """Get metadata for one credential set (masked; never decrypted)."""
    user_id = _user_id_from_payload(payload)
    meta = get_credential_metadata(user_id, cred_id)
    if not meta:
        raise HTTPException(404, "credential not found")
    return {"credential": meta}


@router.put("/api/credentials/{cred_id}")
async def credentials_update(cred_id: str, req: UpdateCredentialRequest,
                              payload=Depends(verify_token)):
    """Update name and/or fields for a credential set."""
    user_id = _user_id_from_payload(payload)
    if not req.name and not req.fields:
        raise HTTPException(400, "must provide name or fields")
    if req.name and len(req.name) > 80:
        raise HTTPException(400, "name must be 1-80 chars")
    try:
        ok = update_credential(user_id, cred_id, req.name, req.fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not ok:
        raise HTTPException(404, "credential not found")
    meta = get_credential_metadata(user_id, cred_id)
    return {"updated": True, "credential": meta}


@router.delete("/api/credentials/{cred_id}")
async def credentials_delete(cred_id: str, payload=Depends(verify_token)):
    """Delete a credential set + its usage log entries."""
    user_id = _user_id_from_payload(payload)
    ok = delete_credential(user_id, cred_id)
    if not ok:
        raise HTTPException(404, "credential not found")
    return {"deleted": True, "id": cred_id}


@router.get("/api/credentials/{cred_id}/usage")
async def credentials_usage_one(cred_id: str, limit: int = 100,
                                  payload=Depends(verify_token)):
    """Get usage audit log entries for one credential set."""
    user_id = _user_id_from_payload(payload)
    meta = get_credential_metadata(user_id, cred_id)
    if not meta:
        raise HTTPException(404, "credential not found")
    rows = get_usage_log(user_id, cred_id, max(1, min(limit, 500)))
    return {"usage": rows, "count": len(rows), "credential_id": cred_id}


@router.get("/api/credentials/usage")
async def credentials_usage_all(limit: int = 200, payload=Depends(verify_token)):
    """Get usage audit log entries across all credentials for current user."""
    user_id = _user_id_from_payload(payload)
    rows = get_usage_log(user_id, None, max(1, min(limit, 500)))
    return {"usage": rows, "count": len(rows)}


def register(app):
    app.include_router(router)
