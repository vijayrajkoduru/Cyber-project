"""OAuth introspection endpoint abuse - advisory. VL-FORGE Vuln tier5_api (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: token enum (run with auth)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "oauth_introspection_abuse: token enum (run with auth)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/oauth_introspection_abuse")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="oauth_introspection_abuse",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
