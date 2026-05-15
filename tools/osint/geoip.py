"""IP geolocation via ipinfo.io free API."""
import socket
import requests
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


@router.post("/api/osint/geoip")
async def osint_geoip(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"ipinfo returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip,
                "hostname": d.get("hostname"), "city": d.get("city"),
                "region": d.get("region"), "country": d.get("country"),
                "loc": d.get("loc"), "org": d.get("org"),
                "postal": d.get("postal"), "timezone": d.get("timezone")}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"GeoIP query failed: {e}"}


def register(app):
    app.include_router(router)
