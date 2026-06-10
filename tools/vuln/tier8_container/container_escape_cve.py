"""Container-escape CVE (Leaky Vessels/Dirty Pipe) - advisory (access-gated). VL-FORGE Vuln tier8_container.
Requires a container image reference / registry pull access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: runc/containerd version + trivy"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("container_escape_cve: requires a container image reference / registry pull access - not applicable to an "
                                   "external URL scan. Canonical check: runc/containerd version + trivy")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/container_escape_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="container_escape_cve",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
