"""drone_adsb_ais_passive v2 — VL-FORGE (RF passive)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["radio_passive"]=True
def _r_passive(s):
    return {"name":"drone_adsb_ais_passive (SDR required)","severity":"INFO",
        "evidence":"ADS-B 1090MHz + AIS 161.975/162.025MHz passive capture"}
FINDING_RULES=[_r_passive]
INTEL_FIELDS=[("Radio passive","radio_passive")]
@router.post("/api/recon/drone_adsb_ais_passive")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="drone_adsb_ais_passive",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
