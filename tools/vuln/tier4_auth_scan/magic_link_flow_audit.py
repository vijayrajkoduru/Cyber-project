"""Magic-link/passwordless flow audit - advisory. VL-FORGE Vuln tier4_auth_scan (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: custom auth probe (authenticated)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "magic_link_flow_audit: custom auth probe (authenticated)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/magic_link_flow_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="magic_link_flow_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
