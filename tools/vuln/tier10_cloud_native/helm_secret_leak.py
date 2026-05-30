"""Helm release secret leak - advisory (access-gated). VL-FORGE Vuln tier10_cloud_native.
Requires Kubernetes/cluster or cloud account access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: helm get values <rel>"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("helm_secret_leak: requires Kubernetes/cluster or cloud account access - not applicable to an "
                                   "external URL scan. Canonical check: helm get values <rel>")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/helm_secret_leak")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="helm_secret_leak",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
