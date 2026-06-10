"""Snyk Open Source scan - advisory. VL-FORGE Vuln tier7_sca (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: snyk test (source tree required)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "snyk_open_source: snyk test (source tree required)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/snyk_open_source")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="snyk_open_source",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
