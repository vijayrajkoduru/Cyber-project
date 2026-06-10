"""GCS bucket public-access check - advisory. VL-FORGE Vuln tier9_iac (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: gcp_bucket_brute (or see Recon cloud tier)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "gcs_bucket_public: gcp_bucket_brute (or see Recon cloud tier)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/gcs_bucket_public")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="gcs_bucket_public",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
