"""Passive DNS v2 — VL-FORGE. Historical IP records via free passive DNS APIs."""
import asyncio
import requests
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,h=None,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0",**(h or {})})
        if r.status_code==200: return r.json() if "json" in r.headers.get("Content-Type","") else r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    # Multiple passive DNS sources
    otx=os.environ.get("OTX_API_KEY","")
    pdns_otx=await asyncio.to_thread(_g,f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/passive_dns",
        {"X-OTX-API-KEY":otx} if otx else None)
    pdns_threatcrowd=await asyncio.to_thread(_g,f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={host}")
    historical_ips=set()
    if pdns_otx and isinstance(pdns_otx,dict):
        ctx.source("otx-pdns")
        for e in pdns_otx.get("passive_dns",[]) or []:
            ip=e.get("address","")
            if ip: historical_ips.add(ip)
    if pdns_threatcrowd and isinstance(pdns_threatcrowd,dict):
        ctx.source("threatcrowd")
        for r in pdns_threatcrowd.get("resolutions",[]) or []:
            ip=r.get("ip_address","")
            if ip: historical_ips.add(ip)
    ctx.state.update({"historical_ips":sorted(historical_ips)[:30],
        "historical_ip_count":len(historical_ips),"reachable":bool(historical_ips)})
def _r_historical(s):
    n=s.get("historical_ip_count") or 0
    if n==0: return None
    sev="INFO" if n<5 else ("LOW" if n<20 else "MEDIUM")
    return {"name":f"{n} historical IPs in passive DNS","severity":sev,"cwe":"T1590.005",
        "evidence":"Sample: "+", ".join((s.get("historical_ips") or [])[:5]),
        "remediation":"Old IPs may still serve content / have origin-IP leaks. Check via origin_ip_bypass."}
def _r_clean(s):
    if (s.get("historical_ip_count") or 0)>0: return None
    return {"name":"No passive DNS history","severity":"POSITIVE",
        "evidence":"OTX + ThreatCrowd both empty"}
FINDING_RULES=[_r_historical,_r_clean]
INTEL_FIELDS=[("Historical IPs","historical_ip_count"),("Sample","historical_ips")]
@router.post("/api/recon/passive_dns")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="passive_dns",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["historical_ips","historical_ip_count"])
def register(app): app.include_router(router)
