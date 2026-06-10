"""misp_threat_feed_advisory — MISP threat-sharing instance advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="misp_threat_feed_advisory", target=target,
        findings=[wrap_finding(
            "MISP (Malware Information Sharing Platform) advisory",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="Self-hosted or community MISP instance required. "
                        "Setup: docker-misp on Ubuntu. Once installed, integrate "
                        "via /events/restSearch with PyMISP client. Join CIRCL / "
                        "FIRST.org MISP communities for threat feed sharing.",
            evidence_marker=f"target: {target} | self-hosted MISP required")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/misp_threat_feed_advisory")
@vl_verify()
async def scan_misp_threat_feed_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
