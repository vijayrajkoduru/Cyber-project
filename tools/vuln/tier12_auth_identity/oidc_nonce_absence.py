"""OIDC nonce validation absence - advisory. VL-FORGE Vuln tier12_auth_identity (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: auth-flow probe"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "oidc_nonce_absence: auth-flow probe"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/oidc_nonce_absence")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="oidc_nonce_absence",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
