"""GeoIP lookup — IP to city/country via ip-api.com (free, no API key).

OSINT first-contact passive lookup: ISP / ASN / city / country / lat-lon /
timezone. Single HTTP call; rate-limited to 45 req/min by ip-api free tier.

VL-FOUNDRY Layer 6 (7-check DoD):
  precheck via safe_get · uniform via standard_response · POSITIVE emit
  · severity field · remediation field · evidence_marker · timeout=8s
"""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12


def _resolve(host_or_ip: str) -> str:
    try:
        socket.inet_aton(host_or_ip)
        return host_or_ip
    except OSError:
        try:
            return socket.gethostbyname(host_or_ip)
        except socket.gaierror:
            return host_or_ip


def _clean(target: str) -> str:
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if ":" in target:
        target = target.split(":", 1)[0]
    return target


def _do_scan(req: ScanRequest) -> dict:
    target = _clean((req.target or "").strip())
    ip = _resolve(target)

    r = safe_get(f"http://ip-api.com/json/{ip}?fields=66846719",
                 req=req, timeout=8)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="geoip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="ip-api.com unreachable or rate-limited")
    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="geoip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="ip-api.com returned non-JSON")
    if data.get("status") != "success":
        return standard_response(
            tool="geoip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"ip-api error: {data.get('message', 'unknown')}")

    city = data.get("city", "?")
    country = data.get("country", "?")
    asn = data.get("as", "?")
    isp = data.get("isp", "?")
    evidence = (f"{ip} -> {city}, {data.get('regionName')}, "
                f"{country} ({data.get('countryCode')}) | "
                f"ISP: {isp} | ASN: {asn}")

    findings = [wrap_finding(
        f"GeoIP located — {city}, {country} (ASN {asn})",
        severity="POSITIVE",
        cwe="CWE-200",
        owasp="A05:2021",
        remediation="Public IP geolocation is expected; no action required. "
                    "Use a CDN if you want to obscure backend IP location.",
        evidence_marker=evidence)]

    return standard_response(
        tool="geoip", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary="GeoIP location + ISP + ASN via ip-api.com",
        raw_data={"geoip": data})


@router.post("/api/osint/geoip")
async def scan_geoip(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="geoip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
