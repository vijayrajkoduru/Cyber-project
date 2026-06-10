"""SLSA L3+ pipeline integrity - advisory (access-gated). VL-FORGE Vuln tier13_supply_chain.
Requires source repo / CI pipeline / build artifacts; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: slsa-github-generator"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("build_pipeline_integrity: requires source repo / CI pipeline / build artifacts - not applicable to an "
                                   "external URL scan. Canonical check: slsa-github-generator")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/build_pipeline_integrity")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="build_pipeline_integrity",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
