"""Webapp module - favicon: Favicon hash
Route: POST /api/webapp/favicon
Thin alias of tools.recon.favicon.recon_favicon for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/favicon")
async def webapp_favicon(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.favicon import recon_favicon as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
