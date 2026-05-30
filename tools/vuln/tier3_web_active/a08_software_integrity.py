"""A08 Software & Data Integrity (deser) - advisory. VL-FORGE Vuln tier3_web_active (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: run LIVE via Web App Pentesting (deserialization_probe)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "a08_software_integrity: run LIVE via Web App Pentesting (deserialization_probe)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/a08_software_integrity")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a08_software_integrity",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
