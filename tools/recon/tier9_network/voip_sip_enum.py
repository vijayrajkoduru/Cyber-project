"""VoIP SIP Enum v2 — VL-FORGE. SIP OPTIONS probe."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
_SIP_PORTS=[5060,5061]
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _sip_probe(ip,port,timeout=3):
    msg=(f"OPTIONS sip:test@{ip} SIP/2.0\r\nVia: SIP/2.0/UDP {ip}:{port}\r\n"
         f"From: <sip:test@vulnuslab>\r\nTo: <sip:test@{ip}>\r\n"
         f"Call-ID: vlscan@vulnuslab\r\nCSeq: 1 OPTIONS\r\n\r\n").encode()
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout); s.sendto(msg,(ip,port))
            data,_=s.recvfrom(2048)
            return data.decode("utf-8",errors="ignore")[:500] if data else None
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    res=await asyncio.gather(*[asyncio.to_thread(_sip_probe,ips[0],p) for p in _SIP_PORTS])
    responses={p:r for p,r in zip(_SIP_PORTS,res) if r}
    if responses: ctx.source(f"sip-{len(responses)}")
    # Extract server / user-agent
    server=None
    for r in responses.values():
        for line in r.splitlines():
            if line.lower().startswith(("server:","user-agent:")):
                server=line.split(":",1)[1].strip()[:80]; break
        if server: break
    ctx.state.update({"sip_responses":responses,"sip_server":server,
        "sip_exposed":bool(responses)})
def _r_exposed(s):
    if not s.get("sip_exposed"): return None
    return {"name":"SIP/VoIP service exposed","severity":"MEDIUM","cwe":"CWE-200",
        "evidence":f"Server: {s.get('sip_server') or 'unknown'}",
        "remediation":"SIP servers are scanned for SIP toll fraud. Firewall to trusted SIP peers."}
FINDING_RULES=[_r_exposed]
INTEL_FIELDS=[("IP","ip"),("SIP exposed","sip_exposed"),("Server","sip_server")]
@router.post("/api/recon/voip_sip_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="voip_sip_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["sip_exposed","sip_server"])
def register(app): app.include_router(router)
