"""VirusTotal domain/IP reputation — key-gated, real lookup if key provided."""
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
router = APIRouter()
@router.post("/api/osint/virustotal")
async def osint_vt(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "skipped_reason": "No VirusTotal API key. Free at virustotal.com/getting-started."}
    host = recon_host(req.target)
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{host}",
                         headers={"x-apikey": api_key, "User-Agent": "VulnusLab/1.0"}, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            return {"ok": True, "host": host,
                    "reputation": d.get("reputation"), "categories": d.get("categories", {}),
                    "last_analysis_stats": stats,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)}
        return {"ok": False, "skipped_reason": f"VirusTotal returned {r.status_code}"}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"VT query failed: {e}"}
def register(app):
    app.include_router(router)
