"""JWT JKU/X5U SSRF - advisory. VL-FORGE Vuln tier12_auth_identity (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: jwt_tool + Burp Collaborator"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "jwt_jku_x5u_ssrf: jwt_tool + Burp Collaborator"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/jwt_jku_x5u_ssrf")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="jwt_jku_x5u_ssrf",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
