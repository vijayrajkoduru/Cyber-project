"""Sourcemap Check v2 — VL-FORGE. Probe .map files."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_PATHS=["/static/js/main.js.map","/static/js/bundle.js.map","/js/app.js.map","/dist/main.js.map",
    "/build/static/js/main.js.map","/assets/main.js.map","/app.bundle.js.map","/vendor.js.map"]
def _g(u):
    try: return requests.get(u,timeout=6,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    # Probe common paths
    sem=asyncio.Semaphore(10)
    async def one(p):
        async with sem:
            r=await asyncio.to_thread(_g,base+p)
            if r and r.status_code==200:
                # Validate it's a real sourcemap
                if "sourceMappingURL" in (r.text or "")[:500] or '"version"' in (r.text or "")[:200]:
                    return {"path":p,"size":len(r.content)}
            return None
    results=await asyncio.gather(*[one(p) for p in _PATHS])
    found=[r for r in results if r]
    # Also probe homepage JS files for sourceMappingURL comments
    home=await asyncio.to_thread(_g,base+"/")
    if home and home.status_code==200:
        ctx.source("homepage")
        js_urls=re.findall(r'<script[^>]+src="([^"]+\.js)"',home.text[:30000])
        for js in js_urls[:5]:
            js_url=js if js.startswith("http") else base+("/" if not js.startswith("/") else "")+js
            jr=await asyncio.to_thread(_g,js_url)
            if jr and "sourceMappingURL=" in (jr.text or "")[-500:]:
                m=re.search(r"sourceMappingURL=([^\s\*/]+)",jr.text[-500:])
                if m: found.append({"path":m.group(1)[:120],"source":"comment","size":0})
    if found: ctx.source(f"maps-{len(found)}")
    ctx.state["maps_found"]=found
    ctx.state["maps_count"]=len(found)
    ctx.state["paths_probed"]=len(_PATHS)
    ctx.state["reachable"]=bool(home)
def _r_exposed(s):
    f=s.get("maps_found") or []
    if not f: return None
    return {"name":f"JavaScript source maps exposed ({len(f)})","severity":"MEDIUM","cwe":"CWE-540",
        "owasp":"A05:2021",
        "evidence":"; ".join(m["path"] for m in f[:3]),
        "remediation":"Don't ship .map files to production. Block at WAF/nginx or remove from build."}
def _r_clean(s):
    if s.get("maps_count",0)>0: return None
    if not s.get("reachable"): return None
    return {"name":"No source maps exposed","severity":"POSITIVE",
        "evidence":f"Probed {s.get('paths_probed',0)} common map paths — all 404"}
FINDING_RULES=[_r_exposed,_r_clean]
INTEL_FIELDS=[("Maps found","maps_count"),("Paths probed","paths_probed")]
@router.post("/api/recon/sourcemap_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="sourcemap_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["maps_found","maps_count"])
def register(app): app.include_router(router)
