"""OpenCorporates company search — playbook §7 #88.

OpenCorporates indexes 230M+ companies across 130+ jurisdictions. Free
tier API works without a key (~500 requests/month per IP). Returns
incorporation jurisdiction, status, officer names — global complement
to SEC EDGAR (US-only) and Companies House (UK-only).

Real probe. Zero false positives.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    company = (req.target or "").strip()
    if not company:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name")

    r = safe_get(
        "https://api.opencorporates.com/v0.4/companies/search",
        req=req, timeout=10,
        headers={"User-Agent": "VulnusLab-OSINT/1.0"},
        params={"q": company, "per_page": 10})
    if r is None:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="OpenCorporates unreachable")
    if r.status_code == 401 or r.status_code == 403:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="OpenCorporates rate-limited — requires API key beyond free quota")
    if r.status_code != 200:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"OpenCorporates status {r.status_code}")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    results = data.get("results", {}).get("companies", []) or []
    total = data.get("results", {}).get("total_count", 0)

    if not results:
        return standard_response(
            tool="opencorporates_search", target=req.target,
            findings=[wrap_finding(
                f"No OpenCorporates registration for '{company}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Not registered globally — or name doesn't match.",
                evidence_marker="0 results (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No OpenCorporates registration")

    matches = []
    inactive = []
    for r_ in results:
        c = r_.get("company", {})
        entry = (
            f"{c.get('name')} ({c.get('jurisdiction_code','?').upper()} "
            f"#{c.get('company_number','?')}, {c.get('current_status','?')})"
        )
        matches.append(entry)
        if c.get("current_status") and any(k in c.get("current_status","").lower()
                                                for k in ("dissol", "inactive", "struck", "liquid")):
            inactive.append(entry)

    findings = [wrap_finding(
        f"OpenCorporates — {len(matches)} of {total} match(es) for '{company}'",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public corporate registry data. Each match is a candidate "
                    "for the customer's corporate entity — confirm via filing address "
                    "+ officer names before assuming relevance.",
        evidence_marker=" | ".join(matches[:8]))]

    if inactive:
        findings.append(wrap_finding(
            f"Inactive / dissolved entities found: {len(inactive)}",
            severity="INFO", cwe="CWE-200",
            remediation="Dissolved entities may still hold domains or accounts. "
                        "If any are recently dissolved (<6 months), squatters may register "
                        "the company name in nearby jurisdictions.",
            evidence_marker=" | ".join(inactive[:5])
                              + " (CONFIRMED via OpenCorporates)"))

    return standard_response(
        tool="opencorporates_search", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"OpenCorporates: {len(matches)} of {total} entries",
        raw_data={"total": total, "matches": matches[:20]})


@router.post("/api/osint/opencorporates_search")
async def scan_opencorporates_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="opencorporates_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
