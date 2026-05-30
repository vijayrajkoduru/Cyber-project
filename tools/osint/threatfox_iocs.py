"""abuse.ch ThreatFox IOC lookup — playbook §4 #55.

Free IOC database covering malware-family attribution. Query an IP / domain
/ hash / URL and get back the malware family, threat type, confidence.
Free, no API key required (auth_key=optional).

Real probe. Zero false positives — reports only what ThreatFox curated.
"""
import asyncio
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="threatfox_iocs", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target")

    body = {"query": "search_ioc", "search_term": target}
    r = safe_post(
        "https://threatfox-api.abuse.ch/api/v1/",
        req=req, timeout=8,
        data=json.dumps(body),
        headers={"User-Agent": "VulnusLab-OSINT/1.0",
                  "Content-Type": "application/json"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="threatfox_iocs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"ThreatFox unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="threatfox_iocs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON ThreatFox response")

    if data.get("query_status") == "no_result":
        return standard_response(
            tool="threatfox_iocs", target=req.target,
            findings=[wrap_finding(
                f"ThreatFox has NO IOC for {target}",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Not in any tracked malware family IOC set as of this scan.",
                evidence_marker="query_status=no_result (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per ThreatFox")
    if data.get("query_status") != "ok":
        return standard_response(
            tool="threatfox_iocs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"ThreatFox status={data.get('query_status')}")

    iocs = data.get("data", []) or []
    families = sorted({i.get("malware_printable") or i.get("malware") or "?"
                        for i in iocs})

    findings = [wrap_finding(
        f"ThreatFox FLAGGED — {target} associated with {len(families)} malware family/ies",
        severity="CRITICAL", cvss="9.5", cwe="CWE-829",
        owasp="A06:2021",
        remediation="This IOC is being used by active malware. If outbound: block "
                    "at egress. If inbound: investigate source. If owned: rebuild the "
                    "compromised asset and rotate all credentials.",
        evidence_marker=(
            f"families: {', '.join(families[:8])} | "
            f"threat_types: {', '.join(sorted({i.get('threat_type') or '?' for i in iocs}))} | "
            f"first_seen: {min(i.get('first_seen','9999') for i in iocs)} | "
            f"confidence: {max(i.get('confidence_level',0) or 0 for i in iocs)}% "
            f"(CONFIRMED via ThreatFox)"
        ))]

    return standard_response(
        tool="threatfox_iocs", target=req.target, findings=findings,
        tests_performed=1, vulnerable=True,
        tests_summary=f"ThreatFox: {len(iocs)} IOC entry/ies across {len(families)} families",
        raw_data={"iocs": iocs[:10], "total": len(iocs), "families": families})


@router.post("/api/osint/threatfox_iocs")
async def scan_threatfox_iocs(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="threatfox_iocs", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
