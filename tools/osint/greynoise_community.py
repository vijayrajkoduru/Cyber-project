"""GreyNoise community IP attribution — playbook §4 #57.

Free GreyNoise community endpoint (api.greynoise.io/v3/community/{ip}).
Returns whether an IP is classified as background internet noise (mass
scanner) vs targeted, malicious vs benign, last seen. No key required.

Real probe. Zero false positives.
"""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10


def _resolve(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    if ":" in t: t = t.split(":", 1)[0]
    try:
        socket.inet_aton(t); return t
    except OSError:
        try: return socket.gethostbyname(t)
        except socket.gaierror: return t


def _do_scan(req: ScanRequest) -> dict:
    ip = _resolve((req.target or "").strip())

    r = safe_get(f"https://api.greynoise.io/v3/community/{ip}",
                  req=req, timeout=8,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0",
                            "Accept": "application/json"})
    if r is None or r.status_code == 404:
        return standard_response(
            tool="greynoise_community", target=req.target,
            findings=[wrap_finding(
                f"GreyNoise has not seen {ip} — IP is not internet-background-noise",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Not a known mass-scanner. If you're seeing traffic "
                            "from this IP it's likely TARGETED, not opportunistic.",
                evidence_marker=f"GreyNoise 404 (CONFIRMED) — never observed")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not in GreyNoise")
    if r.status_code != 200:
        return standard_response(
            tool="greynoise_community", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"GreyNoise status {r.status_code} (rate-limit?)")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="greynoise_community", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON GreyNoise")

    classification = data.get("classification", "unknown")
    name = data.get("name", "unknown")
    noise = data.get("noise", False)
    riot = data.get("riot", False)
    last_seen = data.get("last_seen", "?")

    if classification == "malicious":
        sev, cvss = "HIGH", "7.5"
    elif noise and classification == "benign":
        sev, cvss = "INFO", "0.0"
    elif riot:  # known-good service (Google bot, etc.)
        sev, cvss = "POSITIVE", "0.0"
    else:
        sev, cvss = "INFO", "0.0"

    rem = {
        "malicious": "Block at firewall. GreyNoise marks IPs malicious only with "
                     "high confidence (known C2 / exploit attempts).",
        "benign":    "Background internet noise (Shodan, Censys, etc. scanners). "
                     "Generally safe to leave open but consider rate-limiting.",
    }.get(classification, "Cross-reference with paid GreyNoise tier for full context.")

    findings = [wrap_finding(
        f"GreyNoise — {ip}: classification={classification}, name={name}",
        severity=sev, cvss=cvss, cwe="CWE-200",
        remediation=rem,
        evidence_marker=(
            f"classification={classification} | name={name} | "
            f"noise={noise} | riot={riot} | last_seen={last_seen} "
            f"(CONFIRMED via GreyNoise community)"
        ))]

    return standard_response(
        tool="greynoise_community", target=req.target, findings=findings,
        tests_performed=1, vulnerable=(classification == "malicious"),
        tests_summary=f"GreyNoise: {classification}/{name}",
        raw_data=data)


@router.post("/api/osint/greynoise_community")
@vl_verify()
async def scan_greynoise_community(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="greynoise_community", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
