"""Magic-link entropy / replay test - advisory. VL-FORGE Vuln tier12_auth_identity (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: custom + Burp"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "magic_link_entropy: custom + Burp"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/magic_link_entropy")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="magic_link_entropy",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
