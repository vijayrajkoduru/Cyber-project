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
from tools._vl_core.verify import vl_verify

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

    # FRESHNESS + CONFIDENCE GATE: ThreatFox carries first_seen + a
    # confidence_level (0-100). An IOC is only graded high when it is BOTH
    # recent (<=24 months) AND high-confidence. Stale or low-confidence
    # entries (e.g. a brand-lookalike example) stay INFO.
    import datetime as _dt
    max_conf = max((i.get("confidence_level", 0) or 0 for i in iocs), default=0)
    latest_seen = max((str(i.get("first_seen", "") or "")[:10] for i in iocs),
                       default="")
    recent = False
    if len(latest_seen) >= 7 and latest_seen[:4].isdigit():
        try:
            yr, mo = int(latest_seen[:4]), int(latest_seen[5:7] or "1")
            age_months = ((_dt.date.today().year - yr) * 12
                          + (_dt.date.today().month - mo))
            recent = age_months <= 24
        except Exception:
            recent = False

    if recent and max_conf >= 75:
        sev, cvss = "HIGH", "7.5"
    elif recent and max_conf >= 50:
        sev, cvss = "MEDIUM", "5.3"
    elif recent or max_conf >= 50:
        sev, cvss = "LOW", "3.1"
    else:
        sev, cvss = "INFO", "0.0"

    findings = [wrap_finding(
        f"ThreatFox FLAGGED — {target} associated with {len(families)} malware family/ies",
        severity=sev, cvss=cvss, cwe="CWE-829",
        owasp="A06:2021",
        remediation="ThreatFox inclusion is analyst-curated IOC intel, not proof of "
                    "exploitation. Validate freshness + confidence below. If recent and "
                    "high-confidence and owned: rebuild the compromised asset and rotate "
                    "all credentials. If outbound: block at egress. If inbound: investigate.",
        evidence_marker=(
            f"families: {', '.join(families[:8])} | "
            f"threat_types: {', '.join(sorted({i.get('threat_type') or '?' for i in iocs}))} | "
            f"first_seen: {latest_seen or '?'} (recent<=24mo={recent}) | "
            f"confidence: {max_conf}% "
            f"(via ThreatFox)"
        ))]

    return standard_response(
        tool="threatfox_iocs", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=sev in ("MEDIUM", "HIGH"),  # only graded when recent + confident
        tests_summary=f"ThreatFox: {len(iocs)} IOC entry/ies across {len(families)} families",
        raw_data={"iocs": iocs[:10], "total": len(iocs), "families": families})


@router.post("/api/osint/threatfox_iocs")
@vl_verify()
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
