"""Robots + Sitemap v2 — VL-FORGE.

VL-VERIFY: SPA catch-all returns 200+index.html for every path. Naive
robots.txt detection would report "0 disallow rules" as INFO even though
the file doesn't exist. Reject responses matching the SPA canary AND
require valid file markers (User-agent / Disallow for robots.txt;
<urlset> / <loc> for sitemap.xml).
"""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
from tools._framework.spa_canary import detect_spa_catchall_sync, is_same_as_canary
router=APIRouter()
def _g(u):
    try: return requests.get(u,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
_ROBOTS_RX=re.compile(r"^\s*(User-agent|Allow|Disallow|Sitemap)\s*:",re.I|re.M)
_SITEMAP_RX=re.compile(r"<(urlset|sitemapindex|loc)[\s>]",re.I)
def _is_real_robots(body): return bool(_ROBOTS_RX.search(body or ""))
def _is_real_sitemap(body): return bool(_SITEMAP_RX.search(body or ""))
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    spa = await asyncio.to_thread(detect_spa_catchall_sync, base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    robots,sitemap=await asyncio.gather(
        asyncio.to_thread(_g,base+"/robots.txt"),
        asyncio.to_thread(_g,base+"/sitemap.xml"))
    def _real(r, validator):
        if not r or r.status_code!=200: return False
        body = r.text or ""
        if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body","")):
            return False
        return validator(body)
    if _real(robots, _is_real_robots):
        ctx.source("robots.txt")
        ctx.state["robots_txt"]=robots.text[:5000]
        disallows=re.findall(r"Disallow:\s*(\S+)",robots.text,re.I)
        allows=re.findall(r"Allow:\s*(\S+)",robots.text,re.I)
        sitemaps=re.findall(r"Sitemap:\s*(\S+)",robots.text,re.I)
        ctx.state.update({"disallow_paths":disallows[:50],"allow_paths":allows[:30],
            "sitemap_urls":sitemaps,"disallow_count":len(disallows)})
    if _real(sitemap, _is_real_sitemap):
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
