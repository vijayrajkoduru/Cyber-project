"""RPC Endpoint Enum v2 — VL-FORGE. Portmap (port 111) RPC enumeration."""
import asyncio, socket, struct
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
def _portmap_dump(ip,timeout=4):
    # RPC dump call: pmap_dump (proc=4)
    xid=0x12345678
    msg=struct.pack(">IIIIIIIII",xid,0,2,100000,2,4,0,0,0)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg,(ip,111))
            data,_=s.recvfrom(8192)
            return data
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    data=await asyncio.to_thread(_portmap_dump,ips[0])
    if data:
        ctx.source("portmap-111")
        ctx.state["portmap_exposed"]=True
        ctx.state["response_bytes"]=len(data)
def _r_exposed(s):
    if not s.get("portmap_exposed"): return None
    return {"name":"RPC portmap (port 111) exposed","severity":"HIGH","cvss":7.0,
        "cwe":"CWE-200","owasp":"A05:2021",
        "evidence":f"Returned {s.get('response_bytes',0)} bytes — services enumerable",
        "remediation":"Firewall RPC ports (111, 2049/NFS) to trusted IPs."}
FINDING_RULES=[_r_exposed]
INTEL_FIELDS=[("IP","ip"),("Portmap exposed","portmap_exposed")]
@router.post("/api/recon/rpc_endpoint_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="rpc_endpoint_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["portmap_exposed"])
def register(app): app.include_router(router)
