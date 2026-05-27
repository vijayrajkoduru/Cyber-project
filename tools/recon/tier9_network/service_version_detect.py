"""service_version_detect — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_banner, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    probes = [(21,b""),(22,b""),(25,b""),(80,b"GET / HTTP/1.0\r\nHost: "+ctx.host.encode()+b"\r\n\r\n"),
              (110,b""),(143,b""),(443,b""),(587,b""),(993,b""),(3306,b"")]
    services = {}
    for port, p in probes:
        b = await tcp_banner(ip, port, timeout=3, send=p)
        if b: services[port] = b[:200].decode("utf-8","ignore").strip()
    ctx.state["services"] = services
    ctx.source("Banner grab on common service ports")

RULES = [

]

@router.post("/api/recon/service_version_detect")
async def recon_service_version_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="service_version_detect",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Services","services")])

def register(app):
    app.include_router(router)
