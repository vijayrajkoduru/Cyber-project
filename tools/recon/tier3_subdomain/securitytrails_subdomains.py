"""SecurityTrails Subdomains v2 — VL-FORGE (key-gated)."""
import requests
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("SECURITYTRAILS_API_KEY","")
    if not key: ctx.state["api_key_configured"]=False; return
    ctx.state["api_key_configured"]=True
    try:
        r=requests.get(f"https://api.securitytrails.com/v1/domain/{ctx.host}/subdomains",
            headers={"APIKEY":key,"User-Agent":"VulnusLab/1.0"},timeout=15)
        if r.status_code==200:
            d=r.json()
            subs=sorted([f"{s}.{ctx.host}" for s in d.get("subdomains",[])])
            ctx.state["subdomains"]=subs[:200]
            ctx.state["count"]=len(subs)
            ctx.source(f"securitytrails-{len(subs)}")
        elif r.status_code==401: ctx.state["auth_error"]=True
        elif r.status_code==429: ctx.state["rate_limited"]=True
    except: pass
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"SECURITYTRAILS_API_KEY not configured","severity":"INFO",
        "evidence":"Set env var to enable SecurityTrails subdomain lookup (50 free queries/month)"}
def _r_auth(s):
    if not s.get("auth_error"): return None
    return {"name":"SecurityTrails auth failed","severity":"INFO",
        "evidence":"API key rejected — verify SECURITYTRAILS_API_KEY"}
def _r_rate(s):
    if not s.get("rate_limited"): return None
    return {"name":"SecurityTrails rate-limited","severity":"INFO",
        "evidence":"Free tier 50/month exceeded — upgrade or wait"}
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains via SecurityTrails","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5])}
FINDING_RULES=[_r_unkeyed,_r_auth,_r_rate,_r_found]
INTEL_FIELDS=[("API key","api_key_configured"),("Subdomains","count")]
@router.post("/api/recon/securitytrails_subdomains")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="securitytrails_subdomains",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
