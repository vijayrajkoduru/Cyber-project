"""VirusTotal Subdomains v2 — VL-FORGE (key-gated)."""
import requests
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("VIRUSTOTAL_API_KEY","")
    if not key: ctx.state["api_key_configured"]=False; return
    ctx.state["api_key_configured"]=True
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/domains/{ctx.host}/subdomains?limit=200",
            headers={"x-apikey":key},timeout=15)
        if r.status_code==200:
            d=r.json()
            subs=[item.get("id","") for item in (d.get("data") or [])]
            subs=sorted([s for s in subs if s])
            ctx.state["subdomains"]=subs[:200]; ctx.state["count"]=len(subs)
            ctx.source(f"virustotal-{len(subs)}")
        elif r.status_code in (401,403): ctx.state["auth_error"]=True
        elif r.status_code==429: ctx.state["rate_limited"]=True
    except Exception: pass
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"VIRUSTOTAL_API_KEY not configured","severity":"INFO",
        "evidence":"Free tier: 500 requests/day. Sign up at virustotal.com/gui/sign-up"}
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains via VirusTotal","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5])}
def _r_auth(s):
    if not s.get("auth_error"): return None
    return {"name":"VirusTotal auth failed","severity":"INFO","evidence":"Verify VIRUSTOTAL_API_KEY"}
FINDING_RULES=[_r_unkeyed,_r_auth,_r_found]
INTEL_FIELDS=[("API key","api_key_configured"),("Subdomains","count")]
@router.post("/api/recon/virustotal_subdomains")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="virustotal_subdomains",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
