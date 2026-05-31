"""crowdstrike_falcon_advisory — CrowdStrike Falcon Intel advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response

router = APIRouter()


def _do_scan(req):
    return standard_response(
        tool="crowdstrike_falcon_advisory", target=req.target,
        findings=[wrap_finding(
            "CrowdStrike Falcon Intelligence advisory",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="CrowdStrike Falcon X / Intel = enterprise threat intel "
                        "API ($30K+/yr add-on to Falcon EDR). Returns actor profiles, "
                        "MITRE ATT&CK mapping, sandboxed malware analysis. Free "
                        "alternative: AlienVault OTX (already in otx_indicators).",
            evidence_marker="enterprise advisory")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/crowdstrike_falcon_advisory")
async def scan_crowdstrike_falcon_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
