"""SAML scan (sig-wrap/golden SAML) - advisory. VL-FORGE Vuln tier4_auth_scan (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: SAMLRaider (authenticated)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "saml_scan: SAMLRaider (authenticated)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/saml_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="saml_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
