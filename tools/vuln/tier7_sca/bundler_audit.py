"""Ruby gem CVE audit - advisory (access-gated). VL-FORGE Vuln tier7_sca.
Requires project source tree / dependency manifests; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: bundle audit check --update"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("bundler_audit: requires project source tree / dependency manifests - not applicable to an "
                                   "external URL scan. Canonical check: bundle audit check --update")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/bundler_audit")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="bundler_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
