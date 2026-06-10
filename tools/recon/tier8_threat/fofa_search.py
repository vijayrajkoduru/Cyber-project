"""fofa_search — VL-FORGE Threat Intel."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    candidates=["FOFA_SEARCH_API_KEY","FOFA_SEARCH_TOKEN","CENSYS_API_TOKEN","FOFA_KEY","QUAKE_KEY","ZOOMEYE_KEY","MISP_API_KEY"]
    key=next((os.environ.get(c) for c in candidates if os.environ.get(c)),None)
    ctx.state["api_key_configured"]=bool(key)
    if not key:
        ctx.state["skipped_reason"] = "Requires FOFA API key — set env FOFA_API_KEY to enable. Free tiers available at vendor's site."
        return
    if not key: return
    ctx.source("fofa_search-keyed")
    ctx.state["data_available"]=True
def _r_unkeyed(s):
    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly
    # instead of emitting INFO. See skipped_reason set in gather().
    return None


def _r_keyed(s):
    if not s.get("api_key_configured"): return None
    return {"name":"fofa_search ready (intel query on demand)","severity":"INFO",
        "evidence":"API key configured"}
FINDING_RULES=[_r_unkeyed,_r_keyed]
INTEL_FIELDS=[("API key","api_key_configured"),("Data","data_available")]
@router.post("/api/recon/fofa_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="fofa_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
