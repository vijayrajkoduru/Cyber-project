"""Recon-ng wrapper — Kali tool, not bundled in pure-Python build."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
router = APIRouter()
@router.post("/api/osint/recon_ng")
async def osint_reconng(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True,
            "skipped_reason": "Recon-ng not bundled — use crt.sh + harvester + dnstwist tiles for equivalent passive intel."}
def register(app):
    app.include_router(router)
