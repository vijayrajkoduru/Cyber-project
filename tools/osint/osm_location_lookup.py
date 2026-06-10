"""OpenStreetMap Nominatim geocode + reverse-geocode — playbook §6 #81 .

Free, no API key (1 req/sec rate limit, UA required). Forward-geocode
addresses to lat/lon; reverse-geocode lat,lon to nearest place. Target
forms:
  - "address: 123 Main St, City"     → forward
  - "latlon: 12.34, 56.78"           → reverse

Real probe. Zero false positives — only emits Nominatim results.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12
H = {"User-Agent": "VulnusLab-OSINT/1.0 (awsvijju5@gmail.com)"}


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="osm_location_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    # Reverse mode: "latlon: 12.34, 56.78"
    m = re.match(r"^(?:latlon:\s*)?(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)$", target)
    if m:
        lat, lon = m.group(1), m.group(2)
        r = safe_get(
            f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json",
            req=req, timeout=8, headers=H)
        if r is None or r.status_code != 200:
            return standard_response(
                tool="osm_location_lookup", target=req.target, findings=[],
                tests_performed=1, vulnerable=False,
                skipped_reason=f"Nominatim status {r.status_code if r else 'no-conn'}")
        try:
            d = r.json()
        except Exception:
            return standard_response(
                tool="osm_location_lookup", target=req.target, findings=[],
                tests_performed=1, vulnerable=False,
                skipped_reason="non-JSON Nominatim response")
        display = d.get("display_name", "?")
        addr = d.get("address", {}) or {}
        findings = [wrap_finding(
            f"Reverse geocode: {lat},{lon} → {display[:120]}",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Reverse-geocoded via OpenStreetMap Nominatim. "
                        "Always cross-check with Google Maps / Mapillary for "
                        "ground-truth confirmation (OSM coverage varies by region).",
            evidence_marker=(
                f"country={addr.get('country','?')} | "
                f"state={addr.get('state','?')} | "
                f"city={addr.get('city') or addr.get('town') or '?'} | "
                f"road={addr.get('road','?')}"
            ))]
        return standard_response(
            tool="osm_location_lookup", target=req.target, findings=findings,
            tests_performed=1, vulnerable=False,
            tests_summary=f"reverse: {display[:50]}",
            raw_data={"mode": "reverse", "lat": lat, "lon": lon, "result": d})

    # Forward mode
    q = target.replace("address:", "").strip()
    r = safe_get(
        f"https://nominatim.openstreetmap.org/search?q={q}&format=json&limit=5",
        req=req, timeout=8, headers=H)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="osm_location_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Nominatim status {r.status_code if r else 'no-conn'}")
    try:
        results = r.json()
    except Exception:
        return standard_response(
            tool="osm_location_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    if not results:
        return standard_response(
            tool="osm_location_lookup", target=req.target,
            findings=[wrap_finding(
                f"No OSM results for '{q}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Try adding country / postal code; OSM coverage gaps "
                            "exist in some rural and non-Western regions.",
                evidence_marker="Nominatim returned [] (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No OSM match")

    top = results[0]
    findings = [wrap_finding(
        f"Forward geocode top match: {top.get('display_name','?')[:120]}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="OSM Nominatim result. Confidence varies — review the "
                    "importance + type fields.",
        evidence_marker=(
            f"top: lat={top.get('lat','?')}, lon={top.get('lon','?')} | "
            f"type={top.get('type','?')}/{top.get('class','?')} | "
            f"importance={top.get('importance',0):.3f} | "
            f"alt_matches={len(results)-1}"
        ))]

    return standard_response(
        tool="osm_location_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"forward: {len(results)} match(es)",
        raw_data={"mode": "forward", "query": q, "results": results[:5]})


@router.post("/api/osint/osm_location_lookup")
@vl_verify()
async def scan_osm_location_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="osm_location_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
