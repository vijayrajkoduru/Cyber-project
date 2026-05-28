"""HTTP Banner v2 — VL-FORGE."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u):
    try:
        return requests.head(u,timeout=8,verify=False,allow_redirects=True,
            headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    r=await asyncio.to_thread(_g,web_url(ctx.host))
    if not r: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    h={k:v for k,v in r.headers.items()}
    ctx.state["headers"]=h
    ctx.state["server"]=h.get("Server",h.get("server","unknown"))
    ctx.state["powered_by"]=h.get("X-Powered-By",h.get("x-powered-by",""))
    ctx.state["status_code"]=r.status_code
    ctx.source(f"http-{r.status_code}")
def _r_server_version(s):
    srv=s.get("server","")
    if "/" in srv and any(c.isdigit() for c in srv):
        return {"name":f"Server version disclosed: {srv}","severity":"LOW","cwe":"CWE-200",
            "evidence":f"Server: {srv}","remediation":"Hide server tokens"}
def _r_powered_by(s):
    pb=s.get("powered_by","")
    if not pb: return None
    return {"name":f"X-Powered-By: {pb}","severity":"LOW","cwe":"CWE-200","evidence":pb,
        "remediation":"Remove X-Powered-By header"}
def _r_server(s):
    if not s.get("server"): return None
    return {"name":f"Server: {s['server']}","severity":"INFO","evidence":f"Status: {s.get('status_code')}"}
FINDING_RULES=[_r_server_version,_r_powered_by,_r_server]
INTEL_FIELDS=[("Server","server"),("X-Powered-By","powered_by"),("Status","status_code")]
@router.post("/api/recon/http_banner")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="http_banner",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["server","powered_by","status_code","headers"])
def register(app): app.include_router(router)
