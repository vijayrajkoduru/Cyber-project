"""SpiderFoot — heavy Kali OSINT tool, not bundled."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
router = APIRouter()
@router.post("/api/osint/spiderfoot")
async def osint_spiderfoot(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True,
            "skipped_reason": "SpiderFoot not bundled — run the 9 free OSINT/Recon tiles for equivalent breadth."}
def register(app):
    app.include_router(router)
