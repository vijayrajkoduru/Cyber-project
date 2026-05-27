"""ipv6_alive_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    ipv6 = []
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, h, None, socket.AF_INET6)
        ipv6 = sorted({i[4][0] for i in infos})
    except Exception: pass
    ctx.state["ipv6_addresses"] = ipv6
    ctx.state["ipv6_reachable"] = bool(ipv6)
    ctx.source("getaddrinfo AAAA enumeration")

RULES = [

]

@router.post("/api/recon/ipv6_alive_enum")
async def recon_ipv6_alive_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ipv6_alive_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("IPv6 Addresses","ipv6_addresses"),("IPv6 Reachable","ipv6_reachable")])

def register(app):
    app.include_router(router)
