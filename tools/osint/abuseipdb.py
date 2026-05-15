"""AbuseIPDB reputation lookup — key-gated, free tier 1000/day."""
import socket
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
router = APIRouter()
@router.post("/api/osint/abuseipdb")
async def osint_abuseipdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "skipped_reason": "No AbuseIPDB API key. Free at abuseipdb.com/register."}
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": api_key, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                         timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {"ok": True, "ip": ip,
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "country_code": d.get("countryCode"), "isp": d.get("isp"),
                    "total_reports": d.get("totalReports"),
                    "last_reported_at": d.get("lastReportedAt"),
                    "is_whitelisted": d.get("isWhitelisted")}
        return {"ok": False, "skipped_reason": f"AbuseIPDB returned {r.status_code}"}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"AbuseIPDB query failed: {e}"}
def register(app):
    app.include_router(router)
