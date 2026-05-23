"""Webapp module - wayback: Wayback archive URLs
Route: POST /api/webapp/wayback
Thin alias of tools.recon.wayback.recon_wayback for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/wayback")
async def webapp_wayback(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.wayback import recon_wayback as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
