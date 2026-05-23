"""Webapp module - robotsmap: robots/sitemap parser
Route: POST /api/webapp/robotsmap
Thin alias of tools.recon.robotsmap.recon_robotsmap for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/robotsmap")
async def webapp_robotsmap(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.robotsmap import recon_robotsmap as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
