"""Webapp module - param_discovery: Hidden param discovery
Route: POST /api/webapp/param_discovery
Thin alias of tools.recon.params.recon_params for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/param_discovery")
async def webapp_param_discovery(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.params import recon_params as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
