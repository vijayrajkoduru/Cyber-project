"""greynoise_paid_advisory — GreyNoise paid-tier (riot + visualizer) advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="greynoise_paid_advisory", target=target,
        findings=[wrap_finding(
            "GreyNoise Enterprise advisory (paid tier)",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="Free community tier covered by greynoise_community scanner. "
                        "Paid GreyNoise adds: full RIOT (Routable IP & Trust) "
                        "context, visualizer queries, ransomware/APT actor tagging, "
                        "GNQL query language. $5K-$50K/yr. Contact greynoise.io.",
            evidence_marker=f"target: {target} | advisory")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/greynoise_paid_advisory")
@vl_verify()
async def scan_greynoise_paid_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
