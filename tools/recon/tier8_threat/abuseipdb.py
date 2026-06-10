"""AbuseIPDB v2 — VL-FORGE. IP reputation lookup."""
import asyncio, requests, os
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def gather(ctx):
    key=os.environ.get("ABUSEIPDB_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    ips=await _resolve(ctx.host)
    if not ips: return
    ctx.state["ip"]=ips[0]
    try:
        r=await asyncio.to_thread(requests.get,
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress":ips[0],"maxAgeInDays":90,"verbose":""},
            headers={"Key":key,"Accept":"application/json"},timeout=15)
        if r.status_code==200:
            d=r.json().get("data",{})
            ctx.source("abuseipdb")
            ctx.state.update({"abuse_score":d.get("abuseConfidenceScore",0),
                "total_reports":d.get("totalReports",0),"isp":d.get("isp"),
                "domain":d.get("domain"),"country":d.get("countryCode"),
                "usage_type":d.get("usageType")})
    except: pass
def _r_high_abuse(s):
    score=s.get("abuse_score",0)
    if score<25: return None
    sev="CRITICAL" if score>=75 else ("HIGH" if score>=50 else "MEDIUM")
    return {"name":f"IP abuse confidence: {score}%","severity":sev,"cwe":"T1583.003",
        "evidence":f"{s.get('total_reports',0)} reports, ISP: {s.get('isp','?')}",
        "remediation":"IP previously reported for abuse — verify NOT a shared/CDN IP."}
def _r_clean(s):
    if (s.get("abuse_score") or 0)>=25: return None
    if not s.get("api_key_configured"): return None
    return {"name":"IP not abuse-flagged","severity":"POSITIVE",
        "evidence":f"AbuseIPDB score: {s.get('abuse_score',0)}%"}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"ABUSEIPDB_API_KEY not set","severity":"INFO","evidence":"Free 1000/day at abuseipdb.com"}
FINDING_RULES=[_r_high_abuse,_r_clean,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Abuse score","abuse_score"),
    ("Reports","total_reports"),("ISP","isp"),("Country","country")]
@router.post("/api/recon/abuseipdb")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="abuseipdb",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["abuse_score","total_reports","ip"])
def register(app): app.include_router(router)
