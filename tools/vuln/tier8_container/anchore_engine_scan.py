"""Anchore Engine scan - advisory. VL-FORGE Vuln tier8_container (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: anchore-cli (image required)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "anchore_engine_scan: anchore-cli (image required)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/anchore_engine_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="anchore_engine_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
