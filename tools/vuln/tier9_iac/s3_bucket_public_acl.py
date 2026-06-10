"""S3 bucket public read/write - advisory. VL-FORGE Vuln tier9_iac (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: s3scanner (or see Recon cloud tier)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "s3_bucket_public_acl: s3scanner (or see Recon cloud tier)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/s3_bucket_public_acl")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="s3_bucket_public_acl",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
