"""threatfox_check — VL-FORGE Threat Intel. Real abuse.ch ThreatFox IOC search."""
import asyncio, os, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
def _key():
    for c in ("ABUSECH_AUTH_KEY","THREATFOX_AUTH_KEY","THREATFOX_CHECK_API_KEY"):
        if os.environ.get(c): return os.environ[c]
    return None
def _lookup(host,key):
    h={"User-Agent":"VulnusLab/1.0"}
    if key: h["Auth-Key"]=key
    try:
        r=requests.post("https://threatfox-api.abuse.ch/api/v1/",
            json={"query":"search_ioc","search_term":host}, headers=h, timeout=10)
        return r.status_code,(r.json() if r.status_code==200 else None)
    except Exception: return None,None
async def gather(ctx):
    key=_key(); ctx.state["api_key_configured"]=bool(key)
    sc,j=await asyncio.to_thread(_lookup, str(ctx.host), key)
    if j is None:
        ctx.state["auth_required"]=sc in (401,403); return
    ctx.state["queried"]=True; ctx.source("threatfox")
    data=j.get("data") or [] if isinstance(j.get("data"),list) else []
    ctx.state.update({"query_status":j.get("query_status"),"ioc_count":len(data),
        "malware":sorted({d.get("malware_printable","") for d in data if d.get("malware_printable")})[:6]})
def _r_listed(s):
    if not s.get("ioc_count"): return None
    return {"name":"Domain/IP flagged in ThreatFox (%d IOC match(es))"%s["ioc_count"],
        "severity":"HIGH","cwe":"CWE-506",
        "evidence":"Associated malware: "+(", ".join(s.get("malware") or []) or "see ThreatFox"),
        "remediation":"Target appears in threat-intel as an IOC - investigate compromise immediately."}
def _r_clean(s):
    if not s.get("queried") or s.get("ioc_count"): return None
    return {"name":"Not flagged in ThreatFox","severity":"POSITIVE","evidence":"abuse.ch ThreatFox IOC search returned no matches"}
def _r_nokey(s):
    if not s.get("auth_required"): return None
    return {"name":"ThreatFox needs a free abuse.ch Auth-Key","severity":"INFO",
        "evidence":"Free signup at auth.abuse.ch; set ABUSECH_AUTH_KEY to enable real IOC lookup"}
FINDING_RULES=[_r_listed,_r_clean,_r_nokey]
INTEL_FIELDS=[("Auth key","api_key_configured"),("ThreatFox status","query_status"),("IOC matches","ioc_count")]
@router.post("/api/recon/threatfox_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="threatfox_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
