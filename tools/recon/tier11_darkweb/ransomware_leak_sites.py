"""Ransomware Leak Sites v2 — VL-FORGE. ransomware.live API."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.ransomware.live/v2/searchvictims/{ctx.host}",
            timeout=15,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200:
            data=r.json()
            victims=data if isinstance(data,list) else (data.get("victims") or [])
            ctx.source("ransomware.live")
            ctx.state["victims"]=victims[:10]; ctx.state["victim_count"]=len(victims)
    except: pass
def _r_hit(s):
    n=s.get("victim_count",0)
    if n==0: return None
    return {"name":f"Domain in ransomware leak sites ({n} entries)","severity":"CRITICAL","cvss":10.0,
        "cwe":"T1486","owasp":"A09:2021",
        "evidence":"Sample: "+str((s.get("victims") or [{}])[0])[:200],
        "remediation":"CRITICAL — confirms ransomware compromise. Initiate IR immediately."}
def _r_clean(s):
    if s.get("victim_count",0)>0: return None
    return {"name":"Not on ransomware leak sites","severity":"POSITIVE","evidence":"ransomware.live returned 0"}
FINDING_RULES=[_r_hit,_r_clean]
INTEL_FIELDS=[("Victim count","victim_count")]
@router.post("/api/recon/ransomware_leak_sites")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ransomware_leak_sites",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["victims","victim_count"])
def register(app): app.include_router(router)
