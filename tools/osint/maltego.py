"""Maltego — informational guide (Maltego is a desktop tool, not a scanner)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
router = APIRouter()
@router.post("/api/osint/maltego")
async def osint_maltego(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    return {"ok": True, "target": target,
            "guide": [
                "Maltego is a desktop OSINT graphing tool — install from maltego.com.",
                "Free Community Edition runs up to 12 transforms per entity.",
                "Use VulnusLab tile data as Maltego entity seeds.",
                "Recommended transforms: PassiveTotal, VirusTotal, Shodan, HaveIBeenPwned.",
            ],
            "skipped_reason": "Maltego is a desktop tool — this tile is a usage guide."}
def register(app):
    app.include_router(router)
