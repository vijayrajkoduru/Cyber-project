"""containerd/runc CVE - advisory (access-gated). VL-FORGE Vuln tier10_cloud_native.
Requires Kubernetes/cluster or cloud account access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: trivy + version match"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("container_runtime_cve: requires Kubernetes/cluster or cloud account access - not applicable to an "
                                   "external URL scan. Canonical check: trivy + version match")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/container_runtime_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="container_runtime_cve",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
