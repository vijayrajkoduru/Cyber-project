"""API10 Unsafe consumption of 3rd-party APIs - advisory. VL-FORGE Vuln tier5_api (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: chain audit (manual)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "api10_unsafe_third_party: chain audit (manual)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/api10_unsafe_third_party")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api10_unsafe_third_party",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
