"""HaveIBeenPwned domain check — key-gated stub."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
router = APIRouter()
@router.post("/api/osint/hibp")
async def osint_hibp(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "breaches": [],
                "skipped_reason": "HIBP domain search requires a paid Pwned subscription. Get a key at haveibeenpwned.com/API/Key."}
    return {"ok": True, "skipped_reason": "HIBP integration not yet wired."}
def register(app):
    app.include_router(router)
