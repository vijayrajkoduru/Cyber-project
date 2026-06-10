"""stealer_log_search v2 — VL-FORGE."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["api_key_configured"]=bool(os.environ.get("STEALERLOG_API_KEY","") or os.environ.get("REDLINE_API_KEY",""))
def _r_unkeyed(s):
    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly
    # instead of emitting INFO. See skipped_reason set in gather().
    return None


def _r_ready(s):
    if not s.get("api_key_configured"): return None
    return {"name":"stealer_log_search ready","severity":"CRITICAL","cwe":"T1555","evidence":"Infostealer log DB ready"}
FINDING_RULES=[_r_unkeyed,_r_ready]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/stealer_log_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="stealer_log_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
