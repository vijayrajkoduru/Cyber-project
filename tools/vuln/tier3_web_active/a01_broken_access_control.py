"""A01 Broken Access Control (IDOR/traversal) - advisory. VL-FORGE Vuln tier3_web_active (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: run LIVE via the Web App Pentesting module (/api/webapp)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "a01_broken_access_control: run LIVE via the Web App Pentesting module (/api/webapp)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/a01_broken_access_control")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a01_broken_access_control",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
