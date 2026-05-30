"""API mass-assignment - advisory. VL-FORGE Vuln tier5_api (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: JSON property fuzzing (run with auth)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "api_mass_assignment: JSON property fuzzing (run with auth)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/api_mass_assignment")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api_mass_assignment",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
