"""IPv6 Alive Enum v2 — VL-FORGE. AAAA + IPv6 TCP probe."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _resolve(h,rt="AAAA"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x) for x in await r.resolve(h,rt)]
    except Exception: return []
def _v6_probe(ip,port,timeout=3):
    try:
        with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip,port,0,0))==0
    except Exception: return False
async def gather(ctx):
    aaaa=await _resolve(ctx.host,"AAAA")
    if not aaaa: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ipv6_addresses"]=aaaa
    ctx.source(f"aaaa-{len(aaaa)}")
    # Probe common ports on first IPv6
    probes=await asyncio.gather(
        asyncio.to_thread(_v6_probe,aaaa[0],80),
        asyncio.to_thread(_v6_probe,aaaa[0],443),
        asyncio.to_thread(_v6_probe,aaaa[0],22))
    open_v6=[]
    if probes[0]: open_v6.append(80)
    if probes[1]: open_v6.append(443)
    if probes[2]: open_v6.append(22)
    if open_v6: ctx.source(f"v6-open-{len(open_v6)}")
    ctx.state["ipv6_open_ports"]=open_v6
def _r_v6_present(s):
    a=s.get("ipv6_addresses") or []
    if not a: return None
    return {"name":f"IPv6 enabled ({len(a)} address(es))","severity":"INFO","cwe":"T1590.005",
        "evidence":f"AAAA: {a[:3]}",
        "remediation":"Ensure IPv6 firewall rules mirror IPv4 — common oversight area."}
def _r_no_v6(s):
    if s.get("ipv6_addresses"): return None
    return {"name":"No IPv6 records","severity":"INFO","evidence":"AAAA lookup returned 0"}
FINDING_RULES=[_r_v6_present,_r_no_v6]
INTEL_FIELDS=[("IPv6 addresses","ipv6_addresses"),("IPv6 open ports","ipv6_open_ports")]
@router.post("/api/recon/ipv6_alive_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ipv6_alive_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["ipv6_addresses","ipv6_open_ports"])
def register(app): app.include_router(router)
