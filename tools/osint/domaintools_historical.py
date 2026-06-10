"""domaintools_historical — DomainTools historical WHOIS + reverse-WHOIS (paid)."""
import asyncio, base64
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    domain = (req.target or "").strip().lstrip("@")
    creds = (req.auth_bearer or "").strip()
    if ":" not in creds:
        return standard_response(tool="domaintools_historical", target=req.target,
            findings=[wrap_finding(
                "DomainTools requires username:api_key via auth_bearer",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Paid subscription at domaintools.com ($395+/mo). "
                            "Pass auth_bearer=username:API_KEY. Returns historical "
                            "WHOIS records + reverse-WHOIS (find all domains "
                            "registered to same email).",
                evidence_marker=f"domain: {domain} | no API creds")],
            tests_performed=0, vulnerable=False, tests_summary="DomainTools advisory")
    user, key = creds.split(":", 1)
    auth = base64.b64encode(f"{user}:{key}".encode()).decode()
    r = safe_get(f"https://api.domaintools.com/v1/{domain}/whois/history/",
        req=req, timeout=10,
        headers={"Authorization": f"Basic {auth}",
                  "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(tool="domaintools_historical", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"DT {r.status_code if r else 'no-conn'}")
    try: data = r.json().get("response", {})
    except Exception:
        return standard_response(tool="domaintools_historical", target=req.target,
            findings=[], tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    history = data.get("history", []) or []
    return standard_response(
        tool="domaintools_historical", target=req.target,
        findings=[wrap_finding(
            f"DomainTools historical WHOIS: {len(history)} record(s)",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Historical WHOIS reveals registrant email at each "
                        "ownership change — useful for reverse-WHOIS pivot to "
                        "find related infrastructure.",
            evidence_marker=f"{len(history)} historical records (CONFIRMED via DomainTools)")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"DT history: {len(history)}",
        raw_data={"record_count": len(history)})


@router.post("/api/osint/domaintools_historical")
@vl_verify()
async def scan_domaintools_historical(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="domaintools_historical", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
