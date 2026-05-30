"""Sigstore/cosign signature check - advisory (access-gated). VL-FORGE Vuln tier13_supply_chain.
Requires source repo / CI pipeline / build artifacts; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: cosign verify"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("sigstore_cosign_verify: requires source repo / CI pipeline / build artifacts - not applicable to an "
                                   "external URL scan. Canonical check: cosign verify")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/sigstore_cosign_verify")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="sigstore_cosign_verify",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
