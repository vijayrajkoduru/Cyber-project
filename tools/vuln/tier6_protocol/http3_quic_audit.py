"""HTTP/3 QUIC config (0-RTT replay) - advisory. VL-FORGE Vuln tier6_protocol (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: curl --http3"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "http3_quic_audit: curl --http3"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/http3_quic_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="http3_quic_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
