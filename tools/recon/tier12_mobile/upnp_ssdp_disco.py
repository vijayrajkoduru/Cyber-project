"""upnp_ssdp_disco v2 — VL-FORGE (LAN-only)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["lan_only"]=True
def _r_lan(s):
    return {"name":"upnp_ssdp_disco is LAN-only (passive)","severity":"INFO",
        "evidence":"Requires on-network deployment for SSDP multicast capture"}
FINDING_RULES=[_r_lan]
INTEL_FIELDS=[("LAN only","lan_only")]
@router.post("/api/recon/upnp_ssdp_disco")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="upnp_ssdp_disco",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
