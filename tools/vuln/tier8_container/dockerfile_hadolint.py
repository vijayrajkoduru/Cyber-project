"""Dockerfile best-practice lint - advisory (access-gated). VL-FORGE Vuln tier8_container.
Requires a container image reference / registry pull access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: hadolint Dockerfile"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("dockerfile_hadolint: requires a container image reference / registry pull access - not applicable to an "
                                   "external URL scan. Canonical check: hadolint Dockerfile")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/dockerfile_hadolint")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="dockerfile_hadolint",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
