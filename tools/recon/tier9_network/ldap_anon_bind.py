"""LDAP Anonymous Bind v2 — VL-FORGE. Test anon bind on port 389/636."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _probe(ip,port,timeout=4):
    bind_req=b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout); s.connect((ip,port))
            s.send(bind_req)
            r=s.recv(1024)
            return b"\x0a\x01\x00" in r  # BindResponse with resultCode=success
    except: return False
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    res389,res636=await asyncio.gather(
        asyncio.to_thread(_probe,ips[0],389),
        asyncio.to_thread(_probe,ips[0],636))
    if res389: ctx.source("ldap-389-anon")
    if res636: ctx.source("ldaps-636-anon")
    ctx.state["anon_bind_389"]=res389; ctx.state["anon_bind_636"]=res636
def _r_anon(s):
    if not (s.get("anon_bind_389") or s.get("anon_bind_636")): return None
    return {"name":"LDAP anonymous bind allowed","severity":"HIGH","cvss":7.5,
        "cwe":"CWE-287","owasp":"A07:2021",
        "evidence":f"389: {s.get('anon_bind_389')} | 636: {s.get('anon_bind_636')}",
        "remediation":"Disable anonymous bind. OpenLDAP: 'olcDisallows: bind_anon'"}
FINDING_RULES=[_r_anon]
INTEL_FIELDS=[("IP","ip"),("389 anon","anon_bind_389"),("636 anon","anon_bind_636")]
@router.post("/api/recon/ldap_anon_bind")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ldap_anon_bind",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["anon_bind_389","anon_bind_636"])
def register(app): app.include_router(router)
