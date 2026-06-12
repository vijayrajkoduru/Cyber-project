"""Sourcemap Check v2 — VL-FORGE. Probe .map files.

VL-VERIFY: SPA shells can match the `"version"` substring (some React
manifests, MUI themes, etc.), so the existing content gate isn't enough.
Add SPA canary check + require sourcemap-shaped JSON (mappings field) to
fully eliminate FPs.
"""
import asyncio, requests, re
from urllib.parse import urljoin
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.proof_capture import capture_proof
router=APIRouter()
_PATHS=["/static/js/main.js.map","/static/js/bundle.js.map","/js/app.js.map","/dist/main.js.map",
    "/build/static/js/main.js.map","/assets/main.js.map","/app.bundle.js.map","/vendor.js.map"]
def _g(u):
    try: return requests.get(u,timeout=6,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None
def _is_real_sourcemap(body):
    """Real sourcemaps are JSON with 'mappings' field per Source Map Spec v3."""
    if not body: return False
    head = body[:2000]
    return '"mappings"' in head and '"version"' in head
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    spa = await asyncio.to_thread(detect_spa_catchall_sync, base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    # Probe common paths
    sem=asyncio.Semaphore(10)
    async def one(p):
        async with sem:
            r=await asyncio.to_thread(_g,base+p)
            if not r or r.status_code!=200: return None
            body = r.text or ""
            if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body","")):
                return None
            # Real sourcemap = JSON with mappings + version fields.
            # sourceMappingURL inside the body also OK (rare inline case).
            if _is_real_sourcemap(body) or "sourceMappingURL" in body[:500]:
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
                if m:
                    # Resolve the .map relative to the JS file URL so the absolute
                    # path is correct (the comment value is a bare filename), which
                    # lets the VL-PROOF capture below fetch the real artifact.
                    abs_map=urljoin(js_url, m.group(1))
                    found.append({"path":abs_map[:200],"source":"comment","size":0})
    if found: ctx.source(f"maps-{len(found)}")
    ctx.state["maps_found"]=found
    ctx.state["maps_count"]=len(found)
    ctx.state["paths_probed"]=len(_PATHS)
    ctx.state["reachable"]=bool(home)
    # VL-PROOF: screenshot the FIRST confirmed map as visual evidence. capture_proof
    # re-verifies the source-map signal + SPA canary at capture time, so the image
    # can only ever depict the already-confirmed exposure (never a new FP).
    if found:
        p0=found[0]["path"]
        purl=p0 if p0.startswith("http") else base+(p0 if p0.startswith("/") else "/"+p0)
        shot,cap=await asyncio.to_thread(capture_proof,purl,"sourcemap")
        ctx.state["proof_shot"]=shot
        ctx.state["proof_caption"]=cap
        ctx.state["proof_url"]=purl
        ctx.source("proof-captured" if shot else f"proof-skipped: {cap}")
def _r_exposed(s):
    f=s.get("maps_found") or []
    if not f: return None
    out={"name":f"JavaScript source maps exposed ({len(f)})","severity":"MEDIUM","cwe":"CWE-540",
        "owasp":"A05:2021",
        "evidence":"; ".join(m["path"] for m in f[:3]),
        "remediation":"Don't ship .map files to production. Block at WAF/nginx or remove from build."}
    if s.get("proof_shot"):
        out["screenshot"]=s["proof_shot"]
        out["screenshot_caption"]=s.get("proof_caption")
    return out
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
