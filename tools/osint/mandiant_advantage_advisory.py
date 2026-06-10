"""mandiant_advantage_advisory — Mandiant (Google) Advantage threat-intel advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="mandiant_advantage_advisory", target=target,
        findings=[wrap_finding(
            "Mandiant Advantage Threat Intelligence advisory",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="Mandiant (now part of Google Cloud) offers enterprise "
                        "threat intel. API: $30K-$250K/yr. Returns nation-state "
                        "actor attribution, sector-targeted IOCs, custom briefs. "
                        "Best for verticals targeted by APT (finance/gov/defense). "
                        "Free tier: mandiant.com/resources (blog, reports).",
            evidence_marker=f"target: {target} | enterprise advisory")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/mandiant_advantage_advisory")
@vl_verify()
async def scan_mandiant_advantage_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
