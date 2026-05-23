"""Webapp module - cms_detection: CMS fingerprint
Route: POST /api/webapp/cms_detection
Thin alias of tools.vuln.cms.scan_cms for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/cms_detection")
async def webapp_cms_detection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.vuln.cms import scan_cms as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
