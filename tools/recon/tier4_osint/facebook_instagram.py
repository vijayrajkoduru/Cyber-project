"""facebook_instagram — VL-FORGE OSINT scrape."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    h=ctx.host; org=h.split(".")[0]
    sites=[s for s in ["facebook.com","instagram.com"] if s]
    refs=[]
    for site in sites:
        b=await asyncio.to_thread(_g,f"https://www.bing.com/search?q=site%3A{site}+%22{org}%22&count=15")
        if b:
            ctx.source(f"bing-{site}")
            for m in re.findall(rf"https?://(?:www\.)?{re.escape(site)}/[\w/\-\.]+",b[:40000]):
                refs.append(m)
    refs=sorted(set(refs))[:20]
    ctx.state["references"]=refs
    ctx.state["reference_count"]=len(refs)
    ctx.state["platforms_checked"]=sites
def _r_found(s):
    n=s.get("reference_count",0)
    if n==0: return None
    return {"name":f"{n} facebook_instagram reference(s) found","severity":"INFO","cwe":"T1593",
        "evidence":"Sample: "+", ".join((s.get("references") or [])[:3])}
def _r_clean(s):
    if s.get("reference_count",0)>0: return None
    return {"name":"No facebook_instagram references","severity":"POSITIVE",
        "evidence":f"Searched: {s.get('platforms_checked')}"}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("References","reference_count"),("Platforms","platforms_checked")]
@router.post("/api/recon/facebook_instagram")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="facebook_instagram",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["references","reference_count"])
def register(app): app.include_router(router)
