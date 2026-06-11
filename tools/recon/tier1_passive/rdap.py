"""RDAP v2 — VL-FORGE multi-source modern WHOIS replacement."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router = APIRouter()
def _g(u,t=10):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.json()
    except Exception: pass
    return None
async def gather(ctx):
    host=ctx.host
    a,b,c=await asyncio.gather(
        asyncio.to_thread(_g,f"https://rdap.org/domain/{host}"),
        asyncio.to_thread(_g,f"https://rdap.verisign.com/com/v1/domain/{host}"),
        asyncio.to_thread(_g,f"https://www.rdap.net/domain/{host}"))
    primary=a or b or c
    if not primary: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    for n,v in [("rdap.org",a),("verisign",b),("rdap.net",c)]:
        if v: ctx.source(n)
    events={(e.get("eventAction") or "").lower():e.get("eventDate") for e in primary.get("events",[]) or []}
    reg=None; abuse=None
    for ent in primary.get("entities",[]) or []:
        roles=ent.get("roles",[]) or []
        vcard=ent.get("vcardArray",[])
        if len(vcard)>1:
            for it in vcard[1]:
                if len(it)>=4 and it[0]=="fn" and "registrar" in roles: reg=it[3]
                if len(it)>=4 and it[0]=="email" and "abuse" in roles: abuse=it[3]
    ctx.state.update({"handle":primary.get("handle"),"ldhName":primary.get("ldhName"),
        "registration_date":events.get("registration"),"expiration_date":events.get("expiration"),
        "last_changed":events.get("last changed"),"registrar":reg,"abuse_email":abuse,
        "status_flags":primary.get("status",[]) or [],"sources_count":sum(1 for x in [a,b,c] if x)})
def _r_hold(s):
    f=s.get("status_flags") or []
    sh=[x for x in f if "serverHold" in x]
    if sh: return {"name":"Domain has serverHold status","severity":"CRITICAL","cvss":9.0,
        "evidence":", ".join(sh),"remediation":"Registry suspension — contact registrar immediately."}
def _r_chold(s):
    f=s.get("status_flags") or []
    if not any("clientHold" in x for x in f): return None
    return {"name":"Domain has clientHold","severity":"HIGH","cwe":"CWE-298",
        "evidence":", ".join(f[:3]),"remediation":"Resolve clientHold via registrar — domain not active."}
def _r_locked(s):
    f=s.get("status_flags") or []
    locks=[x for x in f if "Prohibited" in x]
    if not locks: return None
    return {"name":f"Domain locked ({len(locks)} flags)","severity":"POSITIVE","evidence":", ".join(locks[:3])}
def _r_reg(s):
    if not s.get("registrar"): return None
    return {"name":f"Registrar (RDAP): {s['registrar']}","severity":"INFO","evidence":"RDAP entities"}
def _r_abuse(s):
    if not s.get("abuse_email"): return None
    return {"name":"RDAP abuse contact present","severity":"POSITIVE","evidence":s["abuse_email"]}
def _r_src(s):
    n=s.get("sources_count") or 0
    if n==0: return None
    return {"name":f"RDAP responded from {n} source(s)","severity":"INFO","evidence":"rdap.org/Verisign/rdap.net"}
def _r_un(s):
    if s.get("reachable"): return None
    return {"name":"RDAP unavailable","severity":"INFO","evidence":"No RDAP responded"}
FINDING_RULES=[_r_hold,_r_chold,_r_locked,_r_reg,_r_abuse,_r_src,_r_un]
INTEL_FIELDS=[("Reachable","reachable"),("Registrar","registrar"),("Registered","registration_date"),
    ("Expires","expiration_date"),("Last changed","last_changed"),("Abuse","abuse_email"),
    ("Status","status_flags"),("Sources","sources_count")]
@router.post("/api/recon/rdap")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="rdap",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["registrar","abuse_email","status_flags"])
def register(app): app.include_router(router)
