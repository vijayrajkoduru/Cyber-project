"""matter_thread_disco v2 — VL-FORGE (LAN-only)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["lan_only"]=True
def _r_lan(s):
    return {"name":"matter_thread_disco is LAN-only (IEEE 802.15.4)","severity":"INFO",
        "evidence":"Requires Matter-capable radio on customer premises"}
FINDING_RULES=[_r_lan]
INTEL_FIELDS=[("LAN only","lan_only")]
@router.post("/api/recon/matter_thread_disco")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="matter_thread_disco",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
