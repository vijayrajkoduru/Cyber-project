"""USPTO patent search — playbook §7 #91.

USPTO PatentsView API is free, no API key. Returns patents matching a
company assignee name. Useful for tech-stack inference + identifying
key engineers / corporate R&D focus during target profiling.

Real probe. Zero false positives.
"""
import asyncio
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 15


def _do_scan(req: ScanRequest) -> dict:
    company = (req.target or "").strip()
    if not company:
        return standard_response(
            tool="uspto_patent_search", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name")

    body = {
        "q": {"assignees.assignee_organization": company},
        "f": ["patent_number", "patent_title", "patent_date",
               "assignees.assignee_organization", "inventors.inventor_name_first",
               "inventors.inventor_name_last"],
        "s": [{"patent_date": "desc"}],
        "o": {"per_page": 15}
    }

    r = safe_post(
        "https://search.patentsview.org/api/v1/patent/",
        req=req, timeout=12,
        data=json.dumps(body),
        headers={"User-Agent": "VulnusLab-OSINT/1.0",
                  "Content-Type": "application/json"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="uspto_patent_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"USPTO unreachable (status={r.status_code if r else 'no-conn'})")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="uspto_patent_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON USPTO response")

    patents = data.get("patents") or []
    total = data.get("total_hits") or 0

    if not patents:
        return standard_response(
            tool="uspto_patent_search", target=req.target,
            findings=[wrap_finding(
                f"No USPTO patents found for '{company}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either not a US patent holder or name doesn't match "
                            "USPTO assignee strings. Try EPO espacenet for European patents.",
                evidence_marker="USPTO returned 0 patents (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No USPTO patents")

    # Inventor extraction
    inventors = set()
    for p in patents:
        for inv in p.get("inventors", []):
            full = f"{inv.get('inventor_name_first','').strip()} {inv.get('inventor_name_last','').strip()}".strip()
            if full and full != " ":
                inventors.add(full)

    sample_titles = [p.get("patent_title", "")[:80] for p in patents[:5]]
    sample_dates = [p.get("patent_date", "?") for p in patents[:5]]

    findings = [wrap_finding(
        f"USPTO — {total:,} patent(s) assigned to '{company}'",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public IP data. Patents reveal tech stack + active R&D. "
                    "Inventor names = pivot points for LinkedIn enum + Email pattern guess "
                    "(cross-reference with email_pattern_guess scanner).",
        evidence_marker=(
            f"total={total} | recent_titles: " +
            " | ".join(f"{d}: {t}" for d, t in zip(sample_dates, sample_titles)) +
            f" | inventors_sample: {', '.join(list(inventors)[:8])}"
            + (' ...' if len(inventors) > 8 else '')
        ))]

    return standard_response(
        tool="uspto_patent_search", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"USPTO: {total} patents / {len(inventors)} inventor names",
        raw_data={"total_hits": total,
                   "recent_patents": [{"num": p.get("patent_number"),
                                         "title": p.get("patent_title"),
                                         "date": p.get("patent_date")}
                                        for p in patents],
                   "inventors": sorted(inventors)})


@router.post("/api/osint/uspto_patent_search")
async def scan_uspto_patent_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="uspto_patent_search", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
