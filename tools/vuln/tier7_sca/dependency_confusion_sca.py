"""Dependency-confusion / typosquat - advisory. VL-FORGE Vuln tier7_sca (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: confused (manifest required)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "dependency_confusion_sca: confused (manifest required)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/dependency_confusion_sca")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="dependency_confusion_sca",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
