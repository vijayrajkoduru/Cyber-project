"""Mapillary street-level imagery search — playbook §6 #82 .

Mapillary (Meta-owned) has a free Graph API for street-level imagery
with an API key (free tier 50k requests/month). Without key, returns
how-to. With auth_bearer=<client_token>, queries the actual imagery
endpoint near a lat/lon for ground-level context.

Target = "lat,lon" decimal pair.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    m = re.match(r"^(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)$", target)
    if not m:
        return standard_response(
            tool="mapillary_location", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be 'lat,lon' decimal pair")
    lat, lon = float(m.group(1)), float(m.group(2))

    token = (req.auth_bearer or "").strip()
    if not token:
        return standard_response(
            tool="mapillary_location", target=req.target,
            findings=[wrap_finding(
                f"Mapillary lookup how-to for {lat},{lon}",
                severity="POSITIVE", cwe="CWE-200",
                remediation=(
                    "Get a free Mapillary client token at "
                    "https://www.mapillary.com/dashboard/developers. Pass via "
                    "auth_bearer. Or browse directly: "
                    f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=18"
                ),
                evidence_marker=f"viewer URL: https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=18 | no token configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="Mapillary token not configured")

    # bbox ~ 100m around point
    delta = 0.001
    bbox = f"{lon-delta},{lat-delta},{lon+delta},{lat+delta}"
    url = (f"https://graph.mapillary.com/images?bbox={bbox}&limit=10"
            f"&fields=id,captured_at,compass_angle,geometry")
    r = safe_get(url, req=req, timeout=10,
                  headers={"Authorization": f"OAuth {token}",
                            "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="mapillary_location", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Mapillary status {r.status_code if r else 'no-conn'} (bad token / rate-limited)")

    try: data = r.json()
    except Exception:
        return standard_response(
            tool="mapillary_location", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON Mapillary")

    images = data.get("data", []) or []
    if not images:
        return standard_response(
            tool="mapillary_location", target=req.target,
            findings=[wrap_finding(
                f"No Mapillary street imagery within 100m of {lat},{lon}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Try a larger radius via direct Mapillary viewer.",
                evidence_marker=f"bbox={bbox} | 0 images (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No nearby imagery")

    sample = [(i.get("id"), i.get("captured_at","?")[:10]) for i in images[:5]]
    findings = [wrap_finding(
        f"Mapillary — {len(images)} street-imagery image(s) near {lat},{lon}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Use captures for OSINT ground-truth confirmation. Image "
                    "captured_at + compass_angle help correlate with EXIF data "
                    "from other photos for cross-source geolocation verification.",
        evidence_marker=" | ".join(
            f"id={i[0]} captured {i[1]}" for i in sample
        ))]

    return standard_response(
        tool="mapillary_location", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"Mapillary: {len(images)} imgs near {lat},{lon}",
        raw_data={"lat": lat, "lon": lon, "image_count": len(images),
                   "sample": sample})


@router.post("/api/osint/mapillary_location")
@vl_verify()
async def scan_mapillary_location(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="mapillary_location", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
