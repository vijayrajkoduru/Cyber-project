"""Webapp module - tech_stack: Tech stack fingerprint
Route: POST /api/webapp/tech_stack
Thin alias of tools.recon.waf_cdn.recon_waf_cdn for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/tech_stack")
async def webapp_tech_stack(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.waf_cdn import recon_waf_cdn as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
