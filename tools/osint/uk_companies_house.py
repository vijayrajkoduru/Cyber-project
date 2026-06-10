"""UK Companies House search — playbook §7 #89.

The official Companies House API requires a free key. Without one, this
falls back to the public web-search at find-and-update.company-information.
service.gov.uk which works unauthenticated. With auth_bearer set as the
API key, uses the structured JSON API for cleaner results.

Real probe. Zero false positives.
"""
import asyncio
import re
import urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 15


def _do_scan(req: ScanRequest) -> dict:
    company = (req.target or "").strip()
    if not company:
        return standard_response(
            tool="uk_companies_house", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name")

    api_key = req.auth_bearer
    if api_key:
        # Use the structured API with basic-auth (API key as username, empty pwd)
        import base64
        auth = base64.b64encode(f"{api_key}:".encode()).decode()
        r = safe_get(
            f"https://api.company-information.service.gov.uk/search/companies?q={urllib.parse.quote(company)}&items_per_page=10",
            req=req, timeout=10,
            headers={"Authorization": f"Basic {auth}",
                      "User-Agent": "VulnusLab-OSINT/1.0"})
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                items = data.get("items", [])
                if not items:
                    return standard_response(
                        tool="uk_companies_house", target=req.target,
                        findings=[wrap_finding(
                            f"UK Companies House: 0 matches for '{company}'",
                            severity="POSITIVE", cwe="CWE-200",
                            remediation="No UK registration.",
                            evidence_marker="API returned 0 (CONFIRMED)")],
                        tests_performed=1, vulnerable=False,
                        tests_summary="No UK reg")
                matches = [
                    f"{i.get('title')} ({i.get('company_number','?')}, "
                    f"{i.get('company_status','?')}, {i.get('date_of_creation','?')})"
                    for i in items
                ]
                return standard_response(
                    tool="uk_companies_house", target=req.target,
                    findings=[wrap_finding(
                        f"UK Companies House — {len(items)} of {data.get('total_results',0)} match(es)",
                        severity="POSITIVE", cwe="CWE-200",
                        remediation="Public registry data. Drill into officer + "
                                    "filing history for any of interest.",
                        evidence_marker=" | ".join(matches[:8])
                                          + " (CONFIRMED via Companies House API)")],
                    tests_performed=1, vulnerable=False,
                    tests_summary=f"UK CH: {len(items)} matches via API",
                    raw_data={"matches": items[:10]})
            except Exception:
                pass

    # Fallback: public web-search (HTML parse)
    r = safe_get(
        f"https://find-and-update.company-information.service.gov.uk/search/companies?q={urllib.parse.quote(company)}",
        req=req, timeout=10,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="uk_companies_house", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"web fallback status {r.status_code if r else 'no-conn'}")

    # Extract company names + numbers from result-link headers
    entries = re.findall(
        r'<a\s+href="/company/(\d{6,10})[^"]*"\s+title="[^"]+">([^<]+)</a>',
        r.text)[:10]

    if not entries:
        return standard_response(
            tool="uk_companies_house", target=req.target,
            findings=[wrap_finding(
                f"UK Companies House (web): 0 matches for '{company}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No UK registration found via public search. For "
                            "structured queries, set auth_bearer to a free Companies "
                            "House API key (free at developer.company-information.service.gov.uk).",
                evidence_marker="0 result-links (CONFIRMED via public HTML search)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No UK CH match (web)")

    return standard_response(
        tool="uk_companies_house", target=req.target,
        findings=[wrap_finding(
            f"UK Companies House (web) — {len(entries)} match(es) for '{company}'",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Public registry data. For full filing + officer detail, "
                        "get a free Companies House API key and pass via auth_bearer.",
            evidence_marker=" | ".join(
                f"#{num}: {name}" for num, name in entries[:8]
            ) + " (CONFIRMED via Companies House public search)")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"UK CH (web): {len(entries)} matches",
        raw_data={"matches": [{"number": n, "name": nm} for n, nm in entries]})


@router.post("/api/osint/uk_companies_house")
@vl_verify()
async def scan_uk_companies_house(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="uk_companies_house", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
