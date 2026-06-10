"""macOS CIS Benchmark - advisory (access-gated). VL-FORGE Vuln tier11_cis.
Requires host OS / platform admin access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: cis-cat-mac"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("macos_cis_benchmark: requires host OS / platform admin access - not applicable to an "
                                   "external URL scan. Canonical check: cis-cat-mac")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/macos_cis_benchmark")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="macos_cis_benchmark",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
