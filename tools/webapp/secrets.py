"""Webapp module - secrets: JS secret scanner
Route: POST /api/webapp/secrets
Thin alias of tools.recon.secrets.recon_secrets for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/secrets")
async def webapp_secrets(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.secrets import recon_secrets as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
