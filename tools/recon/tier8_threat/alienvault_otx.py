"""AlienVault OTX v2 — VL-FORGE. Threat intel from OTX."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("OTX_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    hdr={"X-OTX-API-KEY":key} if key else {}
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{ctx.host}/general",
            headers=hdr,timeout=15)
        if r.status_code==200:
            d=r.json()
            ctx.source("otx")
            pulses=d.get("pulse_info",{}).get("pulses",[])
            ctx.state.update({"pulse_count":len(pulses),
                "pulse_names":[p.get("name") for p in pulses[:5]],
                "validation":d.get("validation",[]),"sections":d.get("sections",[])})
    except Exception: pass
def _r_pulses(s):
    n=s.get("pulse_count",0)
    if n==0: return None
    sev="HIGH" if n>=10 else ("MEDIUM" if n>=3 else "LOW")
    return {"name":f"Domain in {n} OTX threat pulse(s)","severity":sev,"cwe":"T1583",
        "evidence":"Pulses: "+"; ".join((s.get("pulse_names") or [])[:3]),
        "remediation":"Each pulse = associated threat campaign. Review for IOC correlation."}
def _r_clean(s):
    if s.get("pulse_count",0)>0 or not s.get("api_key_configured"): return None
    return {"name":"Not in OTX pulses","severity":"POSITIVE","evidence":"No threat intel matches"}
FINDING_RULES=[_r_pulses,_r_clean]
INTEL_FIELDS=[("API key","api_key_configured"),("Pulses","pulse_count")]
@router.post("/api/recon/alienvault_otx")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="alienvault_otx",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["pulse_count","pulse_names"])
def register(app): app.include_router(router)
