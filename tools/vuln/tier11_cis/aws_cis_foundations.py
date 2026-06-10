"""AWS CIS Foundations - advisory (access-gated). VL-FORGE Vuln tier11_cis.
Requires host OS / platform admin access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: prowler -c cis"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("aws_cis_foundations: requires host OS / platform admin access - not applicable to an "
                                   "external URL scan. Canonical check: prowler -c cis")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/aws_cis_foundations")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="aws_cis_foundations",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
