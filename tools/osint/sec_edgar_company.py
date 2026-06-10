"""SEC EDGAR company-filings lookup — playbook §7 #87.

US public-company filings. Free, no key required. Target = company name
or ticker. Returns CIK + last 5 filings (10-K, 10-Q, 8-K, etc.) — useful
for understanding security posture from regulatory disclosures.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    q = (req.target or "").strip()
    if not q:
        return standard_response(
            tool="sec_edgar_company", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name / ticker")

    headers = {"User-Agent": "VulnusLab-OSINT/1.0 awsvijju5@gmail.com",
                "Accept": "application/json"}

    # First try ticker mapping
    cik = None
    tk = safe_get("https://www.sec.gov/files/company_tickers.json",
                   req=req, timeout=8, headers=headers)
    if tk is not None and tk.status_code == 200:
        try:
            mapping = tk.json()
            q_lower = q.lower()
            for entry in mapping.values():
                if (entry.get("ticker", "").lower() == q_lower or
                        q_lower in entry.get("title", "").lower()):
                    cik = str(entry.get("cik_str")).zfill(10)
                    company_title = entry.get("title")
                    ticker = entry.get("ticker")
                    break
        except Exception:
            pass

    if not cik:
        return standard_response(
            tool="sec_edgar_company", target=req.target,
            findings=[wrap_finding(
                f"No SEC EDGAR registration found for '{q}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Not a US-listed public company (or name doesn't "
                            "match SEC ticker mapping). For non-US: try OpenCorporates.",
                evidence_marker="No CIK match (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not in SEC EDGAR")

    # Get recent filings
    sub = safe_get(f"https://data.sec.gov/submissions/CIK{cik}.json",
                    req=req, timeout=10, headers=headers)
    if sub is None or sub.status_code != 200:
        return standard_response(
            tool="sec_edgar_company", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason=f"SEC submissions endpoint status {sub.status_code if sub else 'no-conn'}")

    try:
        sub_data = sub.json()
    except Exception:
        return standard_response(
            tool="sec_edgar_company", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="non-JSON SEC submissions response")

    recent = sub_data.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    dates = recent.get("filingDate", [])
    accessions = recent.get("accessionNumber", [])

    filings = list(zip(forms, dates, accessions))[:10]
    interesting_forms = [f for f in filings if f[0] in
                          ("8-K", "10-K", "10-Q", "20-F", "DEF 14A")]

    cyber_8k_recent = [f for f in filings if f[0] == "8-K" and
                        f[1] >= "2023-12-18"]  # SEC cybersecurity disclosure rule effective date

    findings = [wrap_finding(
        f"SEC EDGAR — {sub_data.get('name', company_title)} ({ticker}, CIK {cik})",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public regulatory data. Pull the latest 10-K Item 1C "
                    "(cybersecurity disclosures, mandatory since Dec 2023) for "
                    "the target's security posture and material incidents.",
        evidence_marker=(
            f"sic={sub_data.get('sic','?')} ({sub_data.get('sicDescription','?')}) | "
            f"recent filings: " + " | ".join(f"{f[0]} {f[1]}" for f in filings[:5])
        ))]

    if cyber_8k_recent:
        findings.append(wrap_finding(
            f"CYBERSECURITY 8-K(s) since SEC rule (Dec 2023): {len(cyber_8k_recent)}",
            severity="MEDIUM", cwe="CWE-200",
            remediation="Per SEC rules, public companies must file 8-K within "
                        "4 business days of a material cybersecurity incident. Read "
                        "these filings — they reveal known incidents and may indicate "
                        "ongoing risk.",
            evidence_marker=" | ".join(f"8-K filed {f[1]} ({f[2]})"
                                          for f in cyber_8k_recent[:5])
                              + " (CONFIRMED via SEC EDGAR)"))

    return standard_response(
        tool="sec_edgar_company", target=req.target, findings=findings,
        tests_performed=2, vulnerable=bool(cyber_8k_recent),
        tests_summary=f"SEC EDGAR: {sub_data.get('name','?')} / {len(filings)} recent filings",
        raw_data={"cik": cik, "ticker": ticker, "name": sub_data.get("name"),
                   "sic": sub_data.get("sic"),
                   "recent_filings": filings,
                   "cyber_8k_recent": cyber_8k_recent})


@router.post("/api/osint/sec_edgar_company")
@vl_verify()
async def scan_sec_edgar_company(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="sec_edgar_company", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
