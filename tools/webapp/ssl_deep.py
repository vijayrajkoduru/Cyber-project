"""Webapp module - ssl_deep: SSL/TLS deep scan
Route: POST /api/webapp/ssl_deep
Thin alias of tools.recon.ssl_deep.recon_ssl_deep for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/ssl_deep")
async def webapp_ssl_deep(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.ssl_deep import recon_ssl_deep as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
