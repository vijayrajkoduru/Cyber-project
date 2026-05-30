"""OCI signature (cosign/Notary v2) - advisory (access-gated). VL-FORGE Vuln tier8_container.
Requires a container image reference / registry pull access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: cosign verify <image>"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("oci_signature_verify: requires a container image reference / registry pull access - not applicable to an "
                                   "external URL scan. Canonical check: cosign verify <image>")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/oci_signature_verify")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="oci_signature_verify",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
