"""pypi_package_audit v3 — VL-FORGE. Key-gated; no status-as-finding."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    keyed=bool(os.environ.get("GITHUB_TOKEN","") or os.environ.get("PYPI_TOKEN",""))
    ctx.state["api_key_configured"]=keyed
    if not keyed:
        ctx.state["skipped_reason"]="pypi_package_audit: set PYPI_TOKEN or GITHUB_TOKEN to enable package-leak audit"
def _r_unkeyed(s):
    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly
    # instead of emitting INFO. See skipped_reason set in gather().
    return None


FINDING_RULES=[_r_unkeyed]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/pypi_package_audit")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="pypi_package_audit",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
