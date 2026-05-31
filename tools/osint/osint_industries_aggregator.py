"""osint_industries_aggregator — osint.industries multi-source PII aggregator advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="osint_industries_aggregator", target=req.target,
        findings=[wrap_finding(
            "osint.industries multi-source aggregator advisory",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="osint.industries ($60+/mo) aggregates ~50 sources — "
                        "email, phone, username queries return registered services "
                        "+ public profile cross-reference in single response. "
                        "Free alternative pieces in our toolkit: holehe_email_check "
                        "(30 services), sherlock_username (25 platforms), "
                        "hibp_passwords + breaches.",
            evidence_marker=f"target: {target} | paid aggregator")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/osint_industries_aggregator")
async def scan_osint_industries_aggregator(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
