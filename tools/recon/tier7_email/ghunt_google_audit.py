"""ghunt_google_audit — VL-FORGE OSINT (key-gated graceful)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    # Common env-var conventions
    candidates=["GHUNT_GOOGLE_AUDIT_API_KEY","GHUNT_GOOGLE_AUDIT_KEY","INTELX_API_KEY","LEAKCHECK_API_KEY","DEHASHED_API_KEY"]
    key=next((os.environ.get(c) for c in candidates if os.environ.get(c)),None)
    ctx.state["api_key_configured"]=bool(key)
    ctx.state["host"]=ctx.host
    if key: ctx.source("ghunt_google_audit-keyed")
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"ghunt_google_audit requires API key","severity":"INFO",
        "evidence":"Set appropriate env var for ghunt_google_audit intel"}
def _r_keyed(s):
    if not s.get("api_key_configured"): return None
    return {"name":"ghunt_google_audit configured","severity":"INFO",
        "evidence":"API integration ready — query expansion possible on demand"}
FINDING_RULES=[_r_unkeyed,_r_keyed]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/ghunt_google_audit")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ghunt_google_audit",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
