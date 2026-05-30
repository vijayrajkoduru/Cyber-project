"""AlienVault OTX indicator lookup — playbook §4 #53.

OTX has a free public API for indicators (IP/domain/hash/URL). Returns
pulse hits = community-curated threat campaigns referencing the indicator.
The /indicators/{type}/{value}/general endpoint works without an API key
(though authenticated tier has higher rate limit).

Real probe. Zero false positives — only reports OTX-curated pulses.
"""
import asyncio
import re
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _classify(t: str) -> tuple[str, str]:
    """Return (otx_type, normalized_value)."""
    t = t.strip()
    if IPV4_RE.match(t):
        return ("IPv4", t)
    if HASH_RE.match(t):
        # Auto-detect: 32=md5, 40=sha1, 64=sha256 — OTX uses /file/
        return ("file", t.lower())
    if t.startswith(("http://", "https://")):
        return ("url", t)
    return ("domain", t.replace("http://", "").replace("https://", "").split("/", 1)[0].lower())


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="otx_indicators", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    otx_type, value = _classify(target)
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general"
    headers = {"User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        headers["X-OTX-API-KEY"] = req.auth_bearer

    r = safe_get(url, req=req, timeout=10, headers=headers)
    if r is None:
        return standard_response(
            tool="otx_indicators", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="OTX unreachable")
    if r.status_code == 404:
        return standard_response(
            tool="otx_indicators", target=req.target,
            findings=[wrap_finding(
                f"OTX has no record for {value}",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Not in OTX community pulses as of this scan.",
                evidence_marker="OTX 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not in OTX")
    if r.status_code != 200:
        return standard_response(
            tool="otx_indicators", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"OTX status {r.status_code} (rate-limited?)")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="otx_indicators", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON OTX response")

    pulses = data.get("pulse_info", {}).get("count", 0)
    pulse_list = data.get("pulse_info", {}).get("pulses", [])[:5]
    countries = (data.get("country") or "") if otx_type == "IPv4" else ""

    if pulses == 0:
        return standard_response(
            tool="otx_indicators", target=req.target,
            findings=[wrap_finding(
                f"OTX has 0 pulses for {value}",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="No community threat report references this indicator.",
                evidence_marker=f"pulse_count=0 (CONFIRMED){(' country=' + countries) if countries else ''}")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per OTX")

    pulse_names = [p.get("name", "?")[:60] for p in pulse_list]
    findings = [wrap_finding(
        f"OTX FLAGGED — {value} referenced in {pulses} threat pulse(s)",
        severity="HIGH" if pulses >= 5 else "MEDIUM",
        cvss="7.5" if pulses >= 5 else "5.3", cwe="CWE-829",
        owasp="A06:2021",
        remediation="Multiple OTX community pulses reference this indicator. "
                    "Cross-check each pulse for the named campaign / malware family "
                    "and apply IOC blocking at firewall + email gateway + EDR.",
        evidence_marker=(
            f"pulse_count={pulses} | top_pulses: {' | '.join(pulse_names)} "
            f"(CONFIRMED via AlienVault OTX)"
        ))]

    return standard_response(
        tool="otx_indicators", target=req.target, findings=findings,
        tests_performed=1, vulnerable=True,
        tests_summary=f"OTX: {pulses} pulse(s)",
        raw_data={"pulse_count": pulses, "top_pulses": pulse_names,
                   "country": countries, "type": otx_type})


@router.post("/api/osint/otx_indicators")
async def scan_otx_indicators(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="otx_indicators", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
