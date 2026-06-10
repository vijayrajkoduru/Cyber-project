"""Trivy image CVE scan - advisory (access-gated). VL-FORGE Vuln tier8_container.
Requires a container image reference / registry pull access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: trivy image <image>"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("trivy_image_scan: requires a container image reference / registry pull access - not applicable to an "
                                   "external URL scan. Canonical check: trivy image <image>")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/trivy_image_scan")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="trivy_image_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
