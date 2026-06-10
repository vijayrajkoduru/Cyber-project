"""gha_secret_leak_logs v3 — VL-FORGE (key-gated; no status-as-finding)."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    keyed=bool(os.environ.get("GITHUB_TOKEN",""))
    ctx.state["api_key_configured"]=keyed
    if not keyed:
        ctx.state["skipped_reason"]="gha_secret_leak_logs: set GITHUB_TOKEN to enable GitHub Actions log scanning"
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"gha_secret_leak_logs requires GITHUB_TOKEN","severity":"INFO",
        "evidence":"Set GITHUB_TOKEN to enable GitHub Actions log scan"}
FINDING_RULES=[_r_unkeyed]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/gha_secret_leak_logs")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="gha_secret_leak_logs",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
