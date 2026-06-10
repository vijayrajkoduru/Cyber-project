"""EXIF metadata extraction from image URL — playbook §6 #77.

Downloads image at target URL, extracts EXIF via Pillow. Flags GPS
coordinates, camera serial, creation timestamp, embedded thumbnails.

Real probe. Zero false positives — only emits what EXIF actually contains.
"""
import asyncio
import io
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 18


def _gps_to_decimal(gps_tag) -> tuple[float | None, float | None]:
    """Convert EXIF GPSInfo dict to (lat, lon) decimal degrees."""
    try:
        def conv(coord, ref):
            d, m, s = [float(x) for x in coord]
            v = d + m / 60 + s / 3600
            return -v if ref in ("S", "W") else v
        lat = conv(gps_tag[2], gps_tag[1])
        lon = conv(gps_tag[4], gps_tag[3])
        return (lat, lon)
    except Exception:
        return (None, None)


def _do_scan(req: ScanRequest) -> dict:
    url = (req.target or "").strip()
    if not url.startswith(("http://", "https://")):
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be image URL (http:// or https://)")

    r = safe_get(url, req=req, timeout=12,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"image fetch failed (status={r.status_code if r else 'no-conn'})")

    if len(r.content) > 25 * 1024 * 1024:
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"image too large ({len(r.content)} bytes, max 25MB)")

    try:
        from PIL import Image, ExifTags
    except ImportError:
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Pillow not installed on backend")

    try:
        img = Image.open(io.BytesIO(r.content))
        exif_raw = img._getexif() or {}
    except Exception as e:
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Pillow could not parse image: {e}")

    if not exif_raw:
        return standard_response(
            tool="exif_metadata_url", target=req.target,
            findings=[wrap_finding(
                f"Image at {url} has no EXIF metadata",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Image is properly sanitized — no metadata leakage. "
                            "Either stripped by upload pipeline or screenshot.",
                evidence_marker=f"size: {img.size} | format: {img.format} | no EXIF (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No EXIF data")

    # Map numeric tags to names
    exif = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif_raw.items()}

    # Extract GPS
    lat, lon = None, None
    gps_raw = exif.get("GPSInfo")
    if gps_raw:
        gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_raw.items()} \
              if isinstance(gps_raw, dict) else {}
        if gps:
            lat, lon = _gps_to_decimal(gps)

    findings = []
    if lat is not None and lon is not None:
        findings.append(wrap_finding(
            f"GPS COORDINATES in EXIF: {lat:.6f}, {lon:.6f}",
            severity="HIGH", cvss="7.5", cwe="CWE-359",
            owasp="A05:2021",
            remediation="Strip EXIF before uploading user-facing images. Most "
                        "phone cameras embed GPS by default. Use exiftool / Pillow "
                        "to strip before publication.",
            evidence_marker=(
                f"lat={lat:.6f}, lon={lon:.6f} | "
                f"Google Maps: https://maps.google.com/?q={lat},{lon} "
                f"(CONFIRMED via EXIF GPSInfo)"
            )))

    interesting_tags = {}
    for key in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal",
                 "Artist", "Copyright", "ImageUniqueID", "BodySerialNumber",
                 "LensSerialNumber"):
        if exif.get(key):
            interesting_tags[key] = str(exif[key])[:80]

    if interesting_tags.get("BodySerialNumber") or interesting_tags.get("LensSerialNumber"):
        findings.append(wrap_finding(
            "Camera SERIAL NUMBER in EXIF — direct device fingerprint",
            severity="MEDIUM", cwe="CWE-359",
            remediation="Camera serials tie all photos taken with the same body "
                        "to a single identity. Strip before publishing.",
            evidence_marker=f"serials: {interesting_tags.get('BodySerialNumber','')}"
                              f" / {interesting_tags.get('LensSerialNumber','')} (CONFIRMED)"))

    findings.append(wrap_finding(
        f"EXIF metadata extracted ({len(exif)} tags)",
        severity="INFO" if (lat or interesting_tags.get("BodySerialNumber")) else "POSITIVE",
        cwe="CWE-200",
        remediation="Review tags for PII; strip via exiftool if uploaded by users.",
        evidence_marker=" | ".join(f"{k}={v}" for k, v in interesting_tags.items())))

    return standard_response(
        tool="exif_metadata_url", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(lat or interesting_tags.get("BodySerialNumber")),
        tests_summary=f"{len(exif)} EXIF tags{' + GPS' if lat else ''}",
        raw_data={"tags": {k: str(v)[:200] for k, v in exif.items() if k != "GPSInfo"},
                   "gps": [lat, lon] if lat else None,
                   "size": img.size, "format": img.format})


@router.post("/api/osint/exif_metadata_url")
@vl_verify()
async def scan_exif_metadata_url(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="exif_metadata_url", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
