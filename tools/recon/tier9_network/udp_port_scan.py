"""UDP Port Scan v2 — VL-FORGE. Common UDP services."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_UDP_PROBES={
    53:b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
    123:b"\x1b"+b"\x00"*47,
    161:b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    137:b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    500:b"\x00"*8+b"\x01\x10\x02\x00"+b"\x00"*16,
    1900:b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
}
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _probe(ip,port,payload,timeout=3):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload,(ip,port))
            data,_=s.recvfrom(2048)
            return port if data else None
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip_scanned"]=ips[0]
    ctx.source(f"target-{ips[0]}")
    sem=asyncio.Semaphore(10)
    async def one(p,payload):
        async with sem: return await asyncio.to_thread(_probe,ips[0],p,payload)
    res=await asyncio.gather(*[one(p,pl) for p,pl in _UDP_PROBES.items()])
    open_ports=sorted([p for p in res if p])
    if open_ports: ctx.source(f"open-udp-{len(open_ports)}")
    ctx.state.update({"open_udp_ports":open_ports,"udp_count":len(open_ports)})
def _r_dangerous(s):
    risky={161:"SNMP",137:"NetBIOS",500:"IKE",1900:"SSDP",123:"NTP"}
    op=s.get("open_udp_ports") or []
    hits=[(p,risky[p]) for p in op if p in risky]
    if not hits: return None
    return {"name":f"UDP services exposed ({len(hits)})","severity":"MEDIUM","cwe":"CWE-668",
        "evidence":"; ".join(f"{n}:{p}" for p,n in hits),
        "remediation":"UDP services are often amp-attack vectors (NTP/SSDP/SNMP). Firewall to trusted sources."}
def _r_count(s):
    n=s.get("udp_count",0)
    if n==0: return None
    return {"name":f"{n} UDP ports responsive","severity":"INFO",
        "evidence":f"Ports: {s.get('open_udp_ports')}"}
def _r_clean(s):
    if s.get("udp_count",0)>0 or not s.get("reachable"): return None
    return {"name":"No UDP services responding","severity":"POSITIVE",
        "evidence":"All probed UDP ports silent"}
FINDING_RULES=[_r_dangerous,_r_count,_r_clean]
INTEL_FIELDS=[("Target IP","ip_scanned"),("Open UDP","open_udp_ports"),("Count","udp_count")]
@router.post("/api/recon/udp_port_scan")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="udp_port_scan",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["open_udp_ports","udp_count"])
def register(app): app.include_router(router)
