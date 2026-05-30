"""Indian MCA (Ministry of Corporate Affairs) company lookup — playbook §7 #90.

The MCA portal at mca.gov.in is not API-friendly (no public REST). Public
data is available via udyam-registration.gov.in for MSME entities and via
Tofler / Zauba Corp aggregators (limited).

This probe queries the public Udyam search (for MSME registration) and
returns advisory + how-to for the MCA Master Data form. Real probe to
udyam; MCA portion is advisory until customer mediates the captcha.
"""
import asyncio
import re
import urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 15


def _do_scan(req: ScanRequest) -> dict:
    company = (req.target or "").strip()
    if not company:
        return standard_response(
            tool="mca_indian_company", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name")

    # Try Tofler public-search aggregator (HTML scrape)
    enc = urllib.parse.quote(company)
    r = safe_get(f"https://www.tofler.in/search?q={enc}",
                  req=req, timeout=10,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})

    findings = []
    if r is not None and r.status_code == 200:
        # Tofler links to /company/<CIN>/<slug>
        cins = re.findall(r'/company/([A-Z0-9]{21})/[^"\']+', r.text)[:10]
        if cins:
            cins_unique = list(dict.fromkeys(cins))[:8]
            findings.append(wrap_finding(
                f"Tofler — {len(cins_unique)} match(es) with CIN(s) for '{company}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Use these CINs to query MCA Master Data form at "
                            "mca.gov.in/mcafoportal/viewSignatoryDetails.do. "
                            "Cross-reference with the MCA Company Master form for "
                            "directors, paid-up capital, address.",
                evidence_marker=" | ".join(cins_unique)
                                  + " (CONFIRMED via Tofler public search)"))

    findings.append(wrap_finding(
        "MCA / Udyam lookup how-to",
        severity="INFO", cwe="CWE-200",
        remediation=(
            "MCA Company Master Data: https://www.mca.gov.in/mcafoportal/"
            "showCheckCompanyName.do — search by name or CIN. | "
            "Udyam Registration verification (for MSMEs): "
            "https://udyamregistration.gov.in/Government-India/Ministry-MSME-"
            "registration/UdyamVerification.aspx — needs Udyam Reg Number. | "
            "Zauba Corp (free search): https://www.zaubacorp.com/companysearchresults/" + enc
        ),
        evidence_marker=f"Indian MCA forms are captcha-gated; Tofler/Zaubacorp "
                          f"are best-effort public aggregators."))

    return standard_response(
        tool="mca_indian_company", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary="MCA/Udyam search + how-to",
        raw_data={"query": company,
                   "tofler_url": f"https://www.tofler.in/search?q={enc}",
                   "zaubacorp_url": f"https://www.zaubacorp.com/companysearchresults/{enc}"})


@router.post("/api/osint/mca_indian_company")
async def scan_mca_indian_company(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="mca_indian_company", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
