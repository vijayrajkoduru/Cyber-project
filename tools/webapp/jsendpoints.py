"""Webapp module - jsendpoints: Endpoints from JS files
Route: POST /api/webapp/jsendpoints
Thin alias of tools.recon.jsendpoints.recon_jsendpoints for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/jsendpoints")
async def webapp_jsendpoints(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.jsendpoints import recon_jsendpoints as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
