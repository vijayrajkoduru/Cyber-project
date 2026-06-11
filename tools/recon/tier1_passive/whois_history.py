"""WHOIS History v2 — VL-FORGE. Historical WHOIS records (key-gated)."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,h=None,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0",**(h or {})})
        if r.status_code==200: return r.json()
    except Exception: pass
    return None
async def gather(ctx):
    host=ctx.host
    st_key=os.environ.get("SECURITYTRAILS_API_KEY","")
    whoxy_key=os.environ.get("WHOXY_API_KEY","")
    history=[]
    if st_key:
        d=await asyncio.to_thread(_g,f"https://api.securitytrails.com/v1/history/{host}/whois",
            {"APIKEY":st_key})
        if d:
            ctx.source("securitytrails-history")
            for h in d.get("result",{}).get("items",[]) or []:
                history.append({"source":"securitytrails",
                    "registrar":(h.get("registrarName") or [None])[0] if isinstance(h.get("registrarName"),list) else h.get("registrarName"),
                    "registrant":h.get("registrantName"),
                    "created":h.get("createdDate"),
                    "expires":h.get("expiresDate")})
    if whoxy_key:
        d=await asyncio.to_thread(_g,f"https://api.whoxy.com/?key={whoxy_key}&history={host}")
        if d:
            ctx.source("whoxy-history")
            for h in d.get("whois_records",[]) or []:
                history.append({"source":"whoxy","registrar":h.get("domain_registrar",{}).get("registrar_name"),
                    "created":h.get("create_date"),"expires":h.get("expiry_date")})
    # Detect ownership changes
    registrars=set(h["registrar"] for h in history if h.get("registrar"))
    registrants=set(h.get("registrant") for h in history if h.get("registrant"))
    ctx.state.update({"history_count":len(history),"history_sample":history[:5],
        "registrar_changes":len(registrars),"registrant_changes":len(registrants),
        "reachable":bool(history),"keys_configured":bool(st_key or whoxy_key)})
def _r_unkeyed(s):
    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly
    # instead of emitting INFO. See skipped_reason set in gather().
    return None


def _r_owner_change(s):
    n=s.get("registrant_changes") or 0
    if n<2: return None
    return {"name":f"Domain ownership changed {n-1} time(s)","severity":"MEDIUM","cwe":"T1583",
        "evidence":f"Distinct registrants in history: {n}",
        "remediation":"Verify legitimacy if recent transfer; could indicate hijack or M&A."}
def _r_registrar_change(s):
    n=s.get("registrar_changes") or 0
    if n<2: return None
    return {"name":f"Registrar changed {n-1} time(s)","severity":"LOW",
        "evidence":f"Distinct registrars: {n}",
        "remediation":"Multiple registrar switches can indicate panic moves."}
def _r_history(s):
    n=s.get("history_count") or 0
    if n==0: return None
    return {"name":f"{n} WHOIS history records found","severity":"INFO",
        "evidence":"Pull full history via SecurityTrails / Whoxy for ownership timeline"}
FINDING_RULES=[_r_owner_change,_r_registrar_change,_r_history,_r_unkeyed]
INTEL_FIELDS=[("History records","history_count"),("Registrar changes","registrar_changes"),
    ("Registrant changes","registrant_changes"),("Keys configured","keys_configured")]
@router.post("/api/recon/whois_history")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="whois_history",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["history_sample","history_count"])
def register(app): app.include_router(router)
