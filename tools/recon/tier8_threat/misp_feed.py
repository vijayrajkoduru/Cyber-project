"""misp_feed — VL-FORGE Threat Intel."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    candidates=["MISP_FEED_API_KEY","MISP_FEED_TOKEN","CENSYS_API_TOKEN","FOFA_KEY","QUAKE_KEY","ZOOMEYE_KEY","MISP_API_KEY"]
    key=next((os.environ.get(c) for c in candidates if os.environ.get(c)),None)
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    ctx.source("misp_feed-keyed")
    ctx.state["data_available"]=True
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"misp_feed requires API key","severity":"INFO",
        "evidence":"Set appropriate env var"}
def _r_keyed(s):
    if not s.get("api_key_configured"): return None
    return {"name":"misp_feed ready (intel query on demand)","severity":"INFO",
        "evidence":"API key configured"}
FINDING_RULES=[_r_unkeyed,_r_keyed]
INTEL_FIELDS=[("API key","api_key_configured"),("Data","data_available")]
@router.post("/api/recon/misp_feed")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="misp_feed",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
