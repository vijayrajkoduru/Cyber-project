"""Nessus/OpenVAS full network scan - advisory. VL-FORGE Vuln tier1_network (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: run a network vuln scanner (Nessus/OpenVAS-GVM) against the host"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "openvas_full_scan: run a network vuln scanner (Nessus/OpenVAS-GVM) against the host"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/openvas_full_scan")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="openvas_full_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
