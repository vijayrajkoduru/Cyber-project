"""SNMP Enum v2 — VL-FORGE. Community string probe."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_COMMUNITIES=["public","private","cisco","admin","manager","write","read"]
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _probe(ip,community,timeout=3):
    payload=b"\x30"+bytes([0x1f+len(community)])+b"\x02\x01\x01\x04"+bytes([len(community)])+community.encode()+b"\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout); s.sendto(payload,(ip,161))
            data,_=s.recvfrom(2048)
            return community if data else None
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    res=await asyncio.gather(*[asyncio.to_thread(_probe,ips[0],c) for c in _COMMUNITIES])
    valid=[c for c in res if c]
    if valid: ctx.source(f"snmp-communities-{len(valid)}")
    ctx.state["valid_communities"]=valid
def _r_default(s):
    valid=s.get("valid_communities") or []
    defaults=[c for c in valid if c in ("public","private")]
    if not defaults: return None
    return {"name":f"SNMP default community strings ({', '.join(defaults)})","severity":"CRITICAL",
        "cvss":9.0,"cwe":"CWE-798","owasp":"A07:2021",
        "evidence":f"Valid: {defaults}","remediation":"Change SNMP community immediately. Use SNMPv3 with auth."}
def _r_clean(s):
    if (s.get("valid_communities") or []): return None
    if not s.get("reachable"): return None
    return {"name":"SNMP not exposed or hardened","severity":"POSITIVE",
        "evidence":"No common community strings accepted"}
FINDING_RULES=[_r_default,_r_clean]
INTEL_FIELDS=[("IP","ip"),("Valid communities","valid_communities")]
@router.post("/api/recon/snmp_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="snmp_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["valid_communities"])
def register(app): app.include_router(router)
