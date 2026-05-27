"""origin_ip_bypass — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host.replace("http://","").replace("https://","").split("/")[0]
    try:
        cdn_ip = await asyncio.to_thread(socket.gethostbyname, h)
    except Exception:
        cdn_ip = ""
    # Try to find origin IP via DNS history (passive)
    candidates = []
    # Heuristic: check mail server IPs (often same network as origin, not behind CDN)
    try:
        import dns.resolver
        mx = await asyncio.to_thread(dns.resolver.resolve, h, "MX", lifetime=4)
        for m in mx:
            host = str(m).split()[-1].rstrip(".")
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, host)
                if ip != cdn_ip: candidates.append({"src":"MX","host":host,"ip":ip})
            except Exception: pass
    except Exception: pass
    ctx.state["cdn_ip"] = cdn_ip
    ctx.state["origin_candidates"] = candidates
    ctx.source("MX-based origin IP discovery heuristic")

RULES = [

]

@router.post("/api/recon/origin_ip_bypass")
async def recon_origin_ip_bypass(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="origin_ip_bypass",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("CDN IP","cdn_ip"),("Origin Candidates","origin_candidates")])

def register(app):
    app.include_router(router)
