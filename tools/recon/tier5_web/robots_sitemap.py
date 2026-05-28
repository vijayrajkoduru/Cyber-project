"""Robots + Sitemap v2 — VL-FORGE."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u):
    try: return requests.get(u,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    robots,sitemap=await asyncio.gather(
        asyncio.to_thread(_g,base+"/robots.txt"),
        asyncio.to_thread(_g,base+"/sitemap.xml"))
    if robots and robots.status_code==200:
        ctx.source("robots.txt")
        ctx.state["robots_txt"]=robots.text[:5000]
        disallows=re.findall(r"Disallow:\s*(\S+)",robots.text,re.I)
        allows=re.findall(r"Allow:\s*(\S+)",robots.text,re.I)
        sitemaps=re.findall(r"Sitemap:\s*(\S+)",robots.text,re.I)
        ctx.state.update({"disallow_paths":disallows[:50],"allow_paths":allows[:30],
            "sitemap_urls":sitemaps,"disallow_count":len(disallows)})
    if sitemap and sitemap.status_code==200:
        ctx.source("sitemap.xml")
        urls=re.findall(r"<loc>([^<]+)</loc>",sitemap.text[:50000])
        ctx.state["sitemap_xml_urls"]=urls[:30]
        ctx.state["sitemap_url_count"]=len(urls)
def _r_disclosed(s):
    dis=s.get("disallow_paths") or []
    sensitive=[d for d in dis if any(k in d.lower() for k in ["admin","internal","staging","backup","test","dev","secret","api","_internal"])]
    if not sensitive: return None
    return {"name":f"Sensitive paths in robots.txt ({len(sensitive)})","severity":"LOW","cwe":"CWE-200",
        "evidence":"Sample: "+", ".join(sensitive[:5]),
        "remediation":"robots.txt is publicly readable — don't disclose secret paths. Use auth instead."}
def _r_robots(s):
    if not s.get("robots_txt"): return None
    return {"name":f"robots.txt: {s.get('disallow_count',0)} disallow rules","severity":"INFO",
        "evidence":f"Sitemaps declared: {s.get('sitemap_urls')}"}
def _r_sitemap(s):
    n=s.get("sitemap_url_count",0)
    if n==0: return None
    return {"name":f"sitemap.xml: {n} URLs","severity":"INFO",
        "evidence":"Sample: "+", ".join((s.get("sitemap_xml_urls") or [])[:3])}
FINDING_RULES=[_r_disclosed,_r_robots,_r_sitemap]
INTEL_FIELDS=[("Disallow count","disallow_count"),("Sitemap URLs","sitemap_url_count")]
@router.post("/api/recon/robots_sitemap")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="robots_sitemap",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["disallow_paths","sitemap_xml_urls","robots_txt"])
def register(app): app.include_router(router)
