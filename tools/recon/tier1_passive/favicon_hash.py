"""Favicon Hash v2 — VL-FORGE. MurmurHash3 + multi-CDN probe."""
import asyncio, requests, base64, codecs, mmh3
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u):
    try:
        r=requests.get(u,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.content
    except: pass
    return None
async def gather(ctx):
    base=web_url(ctx.host).rstrip("/")
    paths=["/favicon.ico","/static/favicon.ico","/assets/favicon.ico","/images/favicon.ico"]
    results=await asyncio.gather(*[asyncio.to_thread(_g, base+p) for p in paths])
    found=None; found_path=None
    for p,r in zip(paths, results):
        if r and len(r)>100: found=r; found_path=p; break
    if not found: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    ctx.source(f"favicon@{found_path}")
    try:
        b64=codecs.encode(base64.b64encode(found),"utf-8")
        h=mmh3.hash(b64)
    except Exception:
        h=None
    ctx.state.update({"favicon_path":found_path,"favicon_size":len(found),
        "favicon_hash":h,"favicon_hash_unsigned":h+2**32 if h and h<0 else h})
    # Known framework favicons (small DB)
    db={-1399433489:"WordPress",-247388890:"Cloudflare-default",
        1738910457:"Drupal",-1473321600:"Joomla",
        158475343:"Apache-default",1730712320:"nginx-default"}
    if h in db:
        ctx.state["favicon_fingerprint"]=db[h]
def _r_fp(s):
    if not s.get("favicon_fingerprint"): return None
    return {"name":f"Favicon fingerprint matches: {s['favicon_fingerprint']}",
        "severity":"INFO","cwe":"T1592","evidence":f"MurmurHash3: {s.get('favicon_hash')}"}
def _r_hash(s):
    h=s.get("favicon_hash")
    if h is None: return None
    return {"name":f"Favicon hash: {h}","severity":"INFO",
        "evidence":f"Path: {s.get('favicon_path')} — pivot via Shodan: http.favicon.hash:{h}",
        "remediation":"Search Shodan with this hash to find sister hosts using same favicon."}
def _r_default(s):
    fp=s.get("favicon_fingerprint","")
    if "default" not in fp.lower(): return None
    return {"name":f"Default {fp} favicon — fingerprint reveal","severity":"LOW","cwe":"CWE-200",
        "evidence":fp,"remediation":"Replace default favicon to avoid trivial tech fingerprinting."}
def _r_un(s):
    if s.get("reachable"): return None
    return {"name":"No favicon found","severity":"INFO","evidence":"All 4 common paths returned no data"}
FINDING_RULES=[_r_default,_r_fp,_r_hash,_r_un]
INTEL_FIELDS=[("Reachable","reachable"),("Favicon path","favicon_path"),
    ("Hash (MMH3)","favicon_hash"),("Size","favicon_size"),("Fingerprint","favicon_fingerprint")]
@router.post("/api/recon/favicon_hash")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="favicon_hash",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["favicon_hash","favicon_fingerprint","favicon_path"])
def register(app): app.include_router(router)
