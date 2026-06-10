"""DNS CVE (NXNSAttack/SAD DNS/Kaminsky) - advisory. VL-FORGE Vuln tier1_network (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: targeted resolver CVE checks (recursive resolver required)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "dns_cve_check: targeted resolver CVE checks (recursive resolver required)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/dns_cve_check")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="dns_cve_check",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
