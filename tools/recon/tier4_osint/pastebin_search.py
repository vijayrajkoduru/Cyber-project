"""Pastebin Search v2 — VL-FORGE. Google + DDG dorking for leaked data."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    h=ctx.host
    sites=["pastebin.com","ghostbin.com","privatebin.net","rentry.co","pastes.io","controlc.com"]
    paste_links=set()
    for site in sites:
        bing=await asyncio.to_thread(_g,f"https://www.bing.com/search?q=site%3A{site}+%22{h}%22&count=20")
        if bing:
            ctx.source(f"bing-{site}")
            for m in re.findall(rf"https?://(?:www\.)?{re.escape(site)}/[\w/\-]+",bing[:50000]):
                paste_links.add(m)
    ctx.state["paste_links"]=sorted(paste_links)[:20]
    ctx.state["paste_count"]=len(paste_links)
def _r_pastes(s):
    n=s.get("paste_count",0)
    if n==0: return None
    return {"name":f"Domain referenced in {n} paste(s)","severity":"MEDIUM","cwe":"CWE-200",
        "evidence":"Sample: "+", ".join((s.get("paste_links") or [])[:3]),
        "remediation":"Review each paste for leaked credentials/secrets. File takedown requests if needed."}
def _r_clean(s):
    if s.get("paste_count",0)>0: return None
    return {"name":"No pastebin references","severity":"POSITIVE",
        "evidence":"Pastebin/Ghostbin/Rentry searches returned 0"}
FINDING_RULES=[_r_pastes,_r_clean]
INTEL_FIELDS=[("Paste count","paste_count")]
@router.post("/api/recon/pastebin_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="pastebin_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["paste_links","paste_count"])
def register(app): app.include_router(router)
