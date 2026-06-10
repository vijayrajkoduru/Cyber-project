"""urlhaus_check — VL-FORGE Threat Intel. Real abuse.ch URLhaus host lookup."""
import asyncio, os, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
def _key():
    for c in ("ABUSECH_AUTH_KEY","URLHAUS_AUTH_KEY","URLHAUS_CHECK_API_KEY"):
        if os.environ.get(c): return os.environ[c]
    return None
def _lookup(host,key):
    h={"User-Agent":"VulnusLab/1.0"}
    if key: h["Auth-Key"]=key
    try:
        r=requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host":host}, headers=h, timeout=10)
        return r.status_code, (r.json() if r.status_code==200 else None)
    except Exception: return None, None
async def gather(ctx):
    key=_key(); ctx.state["api_key_configured"]=bool(key)
    sc,j=await asyncio.to_thread(_lookup, str(ctx.host), key)
    if j is None:
        ctx.state["auth_required"]=sc in (401,403); return
    ctx.state["queried"]=True; ctx.source("urlhaus")
    urls=j.get("urls") or []
    online=[u for u in urls if u.get("url_status")=="online"]
    ctx.state.update({"query_status":j.get("query_status"),"url_count":len(urls),
        "online_count":len(online),"samples":[ (u.get("url") or "")[:80] for u in urls[:5]]})
def _r_listed(s):
    if not s.get("url_count"): return None
    on=s.get("online_count",0)
    return {"name":"Domain listed in URLhaus (%d malware URL(s), %d online)"%(s["url_count"],on),
        "severity":"HIGH" if on else "MEDIUM","cwe":"CWE-506",
        "evidence":"; ".join(s.get("samples") or [])[:200],
        "remediation":"Target is associated with known-malicious URLs - investigate compromise; request delisting after cleanup."}
def _r_clean(s):
    if not s.get("queried") or s.get("url_count"): return None
    return {"name":"Not listed in URLhaus (clean reputation)","severity":"POSITIVE",
        "evidence":"abuse.ch URLhaus host lookup returned no malicious URLs"}
def _r_nokey(s):
    if not s.get("auth_required"): return None
    return {"name":"URLhaus needs a free abuse.ch Auth-Key","severity":"INFO",
        "evidence":"Free signup at auth.abuse.ch; set ABUSECH_AUTH_KEY to enable real malware-reputation lookup"}
FINDING_RULES=[_r_listed,_r_clean,_r_nokey]
INTEL_FIELDS=[("Auth key","api_key_configured"),("URLhaus status","query_status"),("Malware URLs","url_count"),("Online","online_count")]
@router.post("/api/recon/urlhaus_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="urlhaus_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
