"""udp_port_scan — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import udp_probe, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    probes = {53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
             123: b"\x1b" + 47*b"\x00",
             161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
             500: b"\x00"*20}
    responsive = []
    for port, pkt in probes.items():
        r = await udp_probe(ip, port, pkt, timeout=3)
        if r: responsive.append({"port":port,"bytes":len(r)})
    ctx.state["responsive_udp"] = responsive
    ctx.source("UDP probes: DNS/NTP/SNMP/IKE")

RULES = [

]

@router.post("/api/recon/udp_port_scan")
async def recon_udp_port_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="udp_port_scan",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Responsive UDP","responsive_udp")])

def register(app):
    app.include_router(router)
