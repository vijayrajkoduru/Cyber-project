"""Multi-role privilege escalation - advisory. VL-FORGE Vuln tier4_auth_scan (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: run via Web App Pentesting (privilege_escalation, authenticated)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "multirole_privesc: run via Web App Pentesting (privilege_escalation, authenticated)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/multirole_privesc")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="multirole_privesc",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
