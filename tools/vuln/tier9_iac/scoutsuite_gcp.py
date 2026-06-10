"""GCP CSPM (Scout Suite) - advisory (access-gated). VL-FORGE Vuln tier9_iac.
Requires IaC source files / cloud account credentials; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: scout gcp"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("scoutsuite_gcp: requires IaC source files / cloud account credentials - not applicable to an "
                                   "external URL scan. Canonical check: scout gcp")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/scoutsuite_gcp")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="scoutsuite_gcp",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
