"""Webapp module - waf_cdn: WAF/CDN identification
Route: POST /api/webapp/waf_cdn
Thin alias of tools.recon.waf_cdn.recon_waf_cdn for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/waf_cdn")
async def webapp_waf_cdn(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.waf_cdn import recon_waf_cdn as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
