"""SBOM generation (SPDX/CycloneDX) - advisory (access-gated). VL-FORGE Vuln tier7_sca.
Requires project source tree / dependency manifests; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: syft dir:. -o cyclonedx-json"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("sbom_generation: requires project source tree / dependency manifests - not applicable to an "
                                   "external URL scan. Canonical check: syft dir:. -o cyclonedx-json")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/sbom_generation")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="sbom_generation",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
