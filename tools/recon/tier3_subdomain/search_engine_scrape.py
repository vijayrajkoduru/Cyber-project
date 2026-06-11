"""Search Engine Scrape v2 — VL-FORGE. site: dorking."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"Mozilla/5.0 (compatible; VulnusLab)"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    h=ctx.host
    # Bing scrape (no API key needed)
    bing,duckduckgo=await asyncio.gather(
        asyncio.to_thread(_g,f"https://www.bing.com/search?q=site%3A*.{h}&count=50"),
        asyncio.to_thread(_g,f"https://html.duckduckgo.com/html/?q=site%3A*.{h}"))
    subs=set()
    pat=re.compile(rf"https?://([\w\-]+\.{re.escape(h)})",re.I)
    for src,name in [(bing,"bing"),(duckduckgo,"ddg")]:
        if not src: continue
        ctx.source(name)
        for m in pat.findall(src):
            subs.add(m.lower())
    ctx.state.update({"subdomains":sorted(subs)[:50],"count":len(subs),
        "sources":sum(1 for x in [bing,duckduckgo] if x)})
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains indexed by search engines","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5]),
        "remediation":"Public indexing = public knowledge. No remediation other than de-index sensitive endpoints."}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains in search engines","severity":"POSITIVE",
        "evidence":"Bing + DDG site:* returned 0"}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Subdomains","count"),("Sources","sources")]
@router.post("/api/recon/search_engine_scrape")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="search_engine_scrape",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
