"""HIBP Breach Check v2 — VL-FORGE. Have I Been Pwned domain search."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("HIBP_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    try:
        r=await asyncio.to_thread(requests.get,f"https://haveibeenpwned.com/api/v3/breaches?domain={ctx.host}",
            timeout=15,headers={"hibp-api-key":key,"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200:
            breaches=r.json() or []
            ctx.source(f"hibp-{len(breaches)}")
            ctx.state["breaches"]=[{"name":b.get("Name"),"date":b.get("BreachDate"),
                "pwn_count":b.get("PwnCount",0),"data_classes":b.get("DataClasses",[])} for b in breaches]
            ctx.state["breach_count"]=len(breaches)
            ctx.state["total_pwned"]=sum(b.get("PwnCount",0) for b in breaches)
        elif r.status_code==401: ctx.state["auth_error"]=True
        elif r.status_code==429: ctx.state["rate_limited"]=True
    except: pass
def _r_breaches(s):
    n=s.get("breach_count",0)
    if n==0: return None
    sev="CRITICAL" if s.get("total_pwned",0)>1000000 else ("HIGH" if n>3 else "MEDIUM")
    return {"name":f"Domain in {n} breach(es), {s.get('total_pwned',0):,} accounts","severity":sev,
        "cwe":"CWE-200","owasp":"A07:2021",
        "evidence":"; ".join(b["name"] for b in (s.get("breaches") or [])[:5]),
        "remediation":"Reset passwords + enforce MFA. Notify affected users per breach disclosure law."}
def _r_no_breach(s):
    if s.get("breach_count",0)>0 or not s.get("api_key_configured"): return None
    return {"name":"No HIBP breaches found","severity":"POSITIVE","evidence":"Domain not in HIBP database"}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"HIBP_API_KEY not set","severity":"INFO","evidence":"Required for breach lookup ($3.95/month)"}
FINDING_RULES=[_r_breaches,_r_no_breach,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Breaches","breach_count"),("Pwned","total_pwned")]
@router.post("/api/recon/hibp_breach_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="hibp_breach_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["breaches","breach_count","total_pwned"])
def register(app): app.include_router(router)
