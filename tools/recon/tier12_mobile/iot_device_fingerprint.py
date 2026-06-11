"""iot_device_fingerprint v2 — VL-FORGE."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["api_key_configured"]=bool(os.environ.get("SHODAN_API_KEY",""))
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"iot_device_fingerprint requires SHODAN_API_KEY","severity":"INFO","evidence":"Set Shodan key"}
def _r_ready(s):
    if not s.get("api_key_configured"): return None
    return {"name":"iot_device_fingerprint ready","severity":"INFO","evidence":"Loaded"}
FINDING_RULES=[_r_unkeyed,_r_ready]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/iot_device_fingerprint")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="iot_device_fingerprint",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
