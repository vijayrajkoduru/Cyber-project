"""Docker CIS Benchmark - advisory (access-gated). VL-FORGE Vuln tier11_cis.
Requires host OS / platform admin access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: docker-bench-security"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("docker_cis: requires host OS / platform admin access - not applicable to an "
                                   "external URL scan. Canonical check: docker-bench-security")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/docker_cis")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="docker_cis",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
