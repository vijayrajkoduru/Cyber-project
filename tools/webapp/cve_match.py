"""Webapp module - cve_match: NVD CVE matching
Route: POST /api/webapp/cve_match
Thin alias of tools.recon.cve_match.recon_cve_match for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/cve_match")
async def webapp_cve_match(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.cve_match import recon_cve_match as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
