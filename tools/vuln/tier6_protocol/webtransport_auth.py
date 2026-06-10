"""WebTransport stream auth audit - advisory. VL-FORGE Vuln tier6_protocol (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: custom + Chrome"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "webtransport_auth: custom + Chrome"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/webtransport_auth")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="webtransport_auth",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
