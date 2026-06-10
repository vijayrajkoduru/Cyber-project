"""Banner Grab v2 — VL-FORGE. Raw TCP banner grabbing."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
_PORTS=[21,22,23,25,80,110,143,443,587,993,995,3306,5432,6379,11211]
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _grab(ip,port,timeout=3):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip,port))
            return s.recv(1024).decode("utf-8",errors="ignore")[:300]
    except: return ""
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    res=await asyncio.gather(*[asyncio.to_thread(_grab,ips[0],p) for p in _PORTS])
    banners={p:b for p,b in zip(_PORTS,res) if b}
    if banners: ctx.source(f"banners-{len(banners)}")
    ctx.state["banners"]=banners; ctx.state["banner_count"]=len(banners)
def _r_banners(s):
    b=s.get("banners") or {}
    if not b: return None
    return {"name":f"Service banners exposed on {len(b)} port(s)","severity":"INFO","cwe":"CWE-200",
        "evidence":"; ".join(f":{p} - {bn[:50]}" for p,bn in list(b.items())[:5])}
def _r_clean(s):
    if s.get("banner_count",0)>0 or not s.get("reachable"): return None
    return {"name":"No banners exposed","severity":"POSITIVE","evidence":"All probed ports silent"}
FINDING_RULES=[_r_banners,_r_clean]
INTEL_FIELDS=[("Target IP","ip"),("Banners","banners"),("Count","banner_count")]
@router.post("/api/recon/banner_grab")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="banner_grab",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["banners","banner_count"])
def register(app): app.include_router(router)
