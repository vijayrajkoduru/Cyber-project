"""VirusTotal Full v2 — VL-FORGE. Domain/IP reputation."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    key=os.environ.get("VIRUSTOTAL_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://www.virustotal.com/api/v3/domains/{ctx.host}",
            headers={"x-apikey":key},timeout=15)
        if r.status_code==200:
            d=r.json().get("data",{}).get("attributes",{})
            ctx.source("virustotal")
            stats=d.get("last_analysis_stats",{})
            ctx.state.update({"malicious":stats.get("malicious",0),
                "suspicious":stats.get("suspicious",0),
                "harmless":stats.get("harmless",0),"reputation":d.get("reputation",0),
                "categories":d.get("categories",{}),
                "creation_date":d.get("creation_date")})
    except: pass
def _r_malicious(s):
    m=s.get("malicious",0)
    if m==0: return None
    sev="CRITICAL" if m>=5 else ("HIGH" if m>=2 else "MEDIUM")
    return {"name":f"{m} VT engines flag domain as malicious","severity":sev,"cwe":"T1583",
        "evidence":f"Malicious: {m}, Suspicious: {s.get('suspicious',0)}, Harmless: {s.get('harmless',0)}",
        "remediation":"Investigate flags via VT GUI. If false positive, request review."}
def _r_suspicious(s):
    if (s.get("malicious",0)>0) or (s.get("suspicious",0)==0): return None
    return {"name":f"{s['suspicious']} VT engines flag domain as suspicious","severity":"LOW",
        "evidence":"Review VT report"}
def _r_clean(s):
    if (s.get("malicious",0)+s.get("suspicious",0))>0: return None
    if not s.get("api_key_configured"): return None
    return {"name":"VirusTotal clean","severity":"POSITIVE",
        "evidence":f"{s.get('harmless',0)} engines mark domain harmless"}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"VIRUSTOTAL_API_KEY not set","severity":"INFO","evidence":"Free 500/day at virustotal.com"}
FINDING_RULES=[_r_malicious,_r_suspicious,_r_clean,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Malicious","malicious"),
    ("Suspicious","suspicious"),("Harmless","harmless"),("Reputation","reputation")]
@router.post("/api/recon/virustotal_full")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="virustotal_full",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["malicious","suspicious","harmless","reputation"])
def register(app): app.include_router(router)
