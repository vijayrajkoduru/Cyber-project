"""Common Crawl v2 — VL-FORGE. CC index search for archived URLs."""
import asyncio, requests, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_INDICES=["CC-MAIN-2024-30","CC-MAIN-2024-22","CC-MAIN-2024-10"]
def _g(u):
    try:
        r=requests.get(u,timeout=15,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    urls=set(); status_codes={}
    tasks=[asyncio.to_thread(_g,
        f"https://index.commoncrawl.org/{idx}-index?url=*.{host}/*&output=json&limit=200") for idx in _INDICES]
    res=await asyncio.gather(*tasks)
    for idx,txt in zip(_INDICES,res):
        if not txt: continue
        ctx.source(f"cc-{idx}")
        for line in txt.splitlines()[:200]:
            try:
                d=json.loads(line)
                u=d.get("url","")
                if host in u:
                    urls.add(u[:200])
                    sc=d.get("status","")
                    status_codes[sc]=status_codes.get(sc,0)+1
            except: continue
    ctx.state["urls_found"]=sorted(urls)[:50]
    ctx.state["urls_count"]=len(urls)
    ctx.state["status_breakdown"]=status_codes
    ctx.state["reachable"]=bool(urls)
def _r_urls(s):
    n=s.get("urls_count") or 0
    if n==0: return None
    return {"name":f"{n} URLs archived in Common Crawl","severity":"INFO","cwe":"T1596",
        "evidence":"Sample: "+", ".join((s.get("urls_found") or [])[:3]),
        "remediation":"Review for sensitive endpoints leaked via search engines."}
def _r_200(s):
    sb=s.get("status_breakdown") or {}
    n=sb.get("200",0) or sb.get(200,0)
    if n<5: return None
    return {"name":f"{n} live URLs (status 200) in CC index","severity":"LOW",
        "evidence":"Indexable content — search engines can find these"}
def _r_clean(s):
    if (s.get("urls_count") or 0)>0: return None
    return {"name":"No Common Crawl history","severity":"POSITIVE",
        "evidence":"Domain not extensively indexed — limited public footprint"}
FINDING_RULES=[_r_urls,_r_200,_r_clean]
INTEL_FIELDS=[("URLs in CC","urls_count"),("Status breakdown","status_breakdown")]
@router.post("/api/recon/common_crawl")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="common_crawl",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["urls_found","urls_count"])
def register(app): app.include_router(router)
