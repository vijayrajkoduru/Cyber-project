"""PyPI supply-chain analysis - advisory (access-gated). VL-FORGE Vuln tier13_supply_chain.
Requires source repo / CI pipeline / build artifacts; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: OSV + provenance"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("pypi_supplychain_audit: requires source repo / CI pipeline / build artifacts - not applicable to an "
                                   "external URL scan. Canonical check: OSV + provenance")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/pypi_supplychain_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="pypi_supplychain_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
