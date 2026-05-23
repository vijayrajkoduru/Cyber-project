"""Webapp module - directory_brute: Directory enumeration
Route: POST /api/webapp/directory_brute
Thin alias of tools.recon.gobuster.recon_gobuster for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/directory_brute")
async def webapp_directory_brute(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.gobuster import recon_gobuster as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
