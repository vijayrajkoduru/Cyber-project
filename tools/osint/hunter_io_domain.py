"""hunter_io_domain — Hunter.io domain-search (email pattern + employees)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    domain = (req.target or "").strip()
    key = (req.auth_bearer or "").strip()
    if not key:
        return standard_response(
            tool="hunter_io_domain", target=req.target,
            findings=[wrap_finding(
                "Hunter.io domain-search requires API key",
                severity="POSITIVE", cwe="CWE-1395",
                remediation="Register free at hunter.io (25 searches/mo free, "
                            "$49/mo plus). Pass auth_bearer=API_KEY. Returns "
                            "email pattern + known employee emails for a domain.",
                evidence_marker=f"domain: {domain} | no API key")],
            tests_performed=0, vulnerable=False,
            tests_summary="Hunter.io advisory")
    r = safe_get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}",
                  req=req, timeout=8,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(tool="hunter_io_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Hunter status {r.status_code if r else 'no-conn'}")
    try: data = r.json().get("data", {})
    except Exception:
        return standard_response(tool="hunter_io_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False, skipped_reason="non-JSON")
    pattern = data.get("pattern", "unknown")
    emails = data.get("emails", []) or []
    return standard_response(
        tool="hunter_io_domain", target=req.target,
        findings=[wrap_finding(
            f"Hunter.io {domain}: pattern={pattern}, {len(emails)} emails found",
            severity="MEDIUM" if len(emails) > 0 else "POSITIVE",
            cvss="5.3" if emails else "0.0",
            cwe="CWE-359", owasp="A05:2021",
            remediation="Public email enumeration. For high-risk employees: "
                        "rotate to non-pattern addresses or use email aliases.",
            evidence_marker=f"pattern={pattern} | sample: " + ", ".join(
                e.get("value", "?") for e in emails[:5]
            ))],
        tests_performed=1, vulnerable=bool(emails),
        tests_summary=f"pattern={pattern}, {len(emails)} emails",
        raw_data={"pattern": pattern, "email_count": len(emails)})


@router.post("/api/osint/hunter_io_domain")
async def scan_hunter_io_domain(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(tool="hunter_io_domain", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
