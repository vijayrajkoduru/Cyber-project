"""Security headers at /api/scan/headers — alias to security_headers."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


@router.post("/api/scan/headers")
async def scan_headers(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.webapp.security_headers import scan_security_headers
    result = await scan_security_headers(req, payload)
    if isinstance(result, dict):
        result["tool"] = "headers"
    return result


def register(app):
    app.include_router(router)
