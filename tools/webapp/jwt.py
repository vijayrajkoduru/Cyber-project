"""Webapp module - jwt: JWT security
Route: POST /api/webapp/jwt
Thin alias of tools.vuln.jwt_scan.scan_jwt for Webapp Pentest customers.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/webapp/jwt")
async def webapp_jwt(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.vuln.jwt_scan import scan_jwt as _impl
    return await _impl(req, payload)


def register(app):
    app.include_router(router)
