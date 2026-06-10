"""npm install-script malware behavior - advisory (access-gated). VL-FORGE Vuln tier13_supply_chain.
Requires source repo / CI pipeline / build artifacts; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: npm audit + custom"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("npm_install_script_audit: requires source repo / CI pipeline / build artifacts - not applicable to an "
                                   "external URL scan. Canonical check: npm audit + custom")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/npm_install_script_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="npm_install_script_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
