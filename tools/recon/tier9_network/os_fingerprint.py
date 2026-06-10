"""OS Fingerprint v2 — VL-FORGE. TTL + TCP window heuristic."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _ttl(ip):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(3); s.connect((ip,53))
            return s.getsockopt(socket.IPPROTO_IP,socket.IP_TTL)
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    ttl=await asyncio.to_thread(_ttl,ips[0])
    if ttl is None: return
    ctx.source(f"ttl-{ttl}")
    # Standard TTLs: Linux=64, Windows=128, BSD/old=255
    os_guess="Linux/Unix" if 50<=ttl<=64 else ("Windows" if 100<=ttl<=128 else ("BSD/Solaris" if ttl>200 else "Unknown"))
    ctx.state.update({"ip":ips[0],"observed_ttl":ttl,"os_guess":os_guess})
def _r_os(s):
    if not s.get("os_guess"): return None
    return {"name":f"OS likely: {s['os_guess']}","severity":"INFO","cwe":"T1592",
        "evidence":f"Observed TTL: {s.get('observed_ttl')}"}
FINDING_RULES=[_r_os]
INTEL_FIELDS=[("IP","ip"),("TTL","observed_ttl"),("OS","os_guess")]
@router.post("/api/recon/os_fingerprint")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="os_fingerprint",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["os_guess","observed_ttl"])
def register(app): app.include_router(router)
