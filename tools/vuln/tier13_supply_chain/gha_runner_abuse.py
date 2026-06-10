"""Self-hosted runner abuse recon - advisory (access-gated). VL-FORGE Vuln tier13_supply_chain.
Requires source repo / CI pipeline / build artifacts; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: gh api repos/:o/:r/actions/runners"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("gha_runner_abuse: requires source repo / CI pipeline / build artifacts - not applicable to an "
                                   "external URL scan. Canonical check: gh api repos/:o/:r/actions/runners")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/gha_runner_abuse")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="gha_runner_abuse",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
