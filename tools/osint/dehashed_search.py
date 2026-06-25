"""dehashed_search — DeHashed breach search (paid API).

DeHashed is a paid service ($5/mo) with the largest breach corpus —
much deeper than HIBP. Without API key, this scanner emits an advisory
with how-to. With auth_bearer set, queries the real API.
"""
import asyncio
import base64
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()

    # VL-VERIFY deep: skip reserved domains. DeHashed will return matches
    # for example.com because the string appears in countless breach
    # samples, but those aren't breaches OF example.com.
    from tools._vl_core.reserved_domains import is_reserved
    if "." in q and is_reserved(q):
        return standard_response(
            tool="dehashed_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("Target is RFC 2606 / 6761 reserved domain. "
                             "DeHashed search is not applicable."))

    creds = (req.auth_bearer or "").strip()
    if ":" not in creds:
        return standard_response(
            tool="dehashed_search", target=req.target,
            findings=[wrap_finding(
                "DeHashed search requires API key (email:api_key via auth_bearer)",
                severity=grade.advisory(), cwe="CWE-1395",
                remediation="Subscribe at https://dehashed.com ($5/mo entry). "
                            "Pass auth_bearer as 'your-email@example.com:YOUR_API_KEY'. "
                            "DeHashed has 14B+ records — deepest paid breach DB.",
                evidence_marker=f"query: {q} | no API key configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="DeHashed advisory mode")
    auth = base64.b64encode(creds.encode()).decode()
    r = safe_get(f"https://api.dehashed.com/search?query={q}",
                  req=req, timeout=8,
                  headers={"Authorization": f"Basic {auth}",
                            "Accept": "application/json",
                            "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="dehashed_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"DeHashed status {r.status_code if r else 'no-conn'}")
    try: data = r.json()
    except Exception:
        return standard_response(
            tool="dehashed_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")
    total = data.get("total", 0)
    entries = data.get("entries", []) or []
    if total == 0:
        return standard_response(
            tool="dehashed_search", target=req.target,
            findings=[wrap_finding(
                f"DeHashed: 0 entries for '{q}'",
                severity=grade.protective(), cwe="CWE-1395",
                remediation="Not in DeHashed breach corpus.",
                evidence_marker="total=0 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Clean per DeHashed")
    return standard_response(
        tool="dehashed_search", target=req.target,
        findings=[wrap_finding(
            f"DeHashed: {total:,} entry/ies for '{q}'",
            severity=(sev := grade.exposure(
                confirmed=True,
                impact='enables' if total >= 10 else 'aids')),
            cvss=grade.cvss_for(sev),
            cwe="CWE-359", owasp="A07:2021",
            remediation="Each entry includes password/hash + source-breach. "
                        "Force password rotation for affected users + monitor "
                        "for credential-stuffing.",
            evidence_marker=f"sources: {set((e.get('database_name') or '?') for e in entries[:10])} "
                              f"(CONFIRMED via DeHashed)")],
        tests_performed=1, vulnerable=True,
        tests_summary=f"DeHashed: {total} entries",
        raw_data={"total": total, "sample": entries[:5]})


@router.post("/api/osint/dehashed_search")
@vl_verify()
async def scan_dehashed_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="dehashed_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
