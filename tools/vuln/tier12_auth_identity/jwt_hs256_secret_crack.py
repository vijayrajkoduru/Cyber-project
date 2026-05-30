"""JWT weak HS256 secret crack - advisory. VL-FORGE Vuln tier12_auth_identity (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: hashcat -m 16500 on a captured token"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "jwt_hs256_secret_crack: hashcat -m 16500 on a captured token"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/jwt_hs256_secret_crack")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="jwt_hs256_secret_crack",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
