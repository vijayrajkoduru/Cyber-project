"""voip_sip_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import udp_probe, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    pkt = (b"OPTIONS sip:nm SIP/2.0\r\n"
           b"Via: SIP/2.0/UDP nm;branch=foo\r\n"
           b"From: <sip:nm@nm>;tag=foo\r\n"
           b"To: <sip:nm2@nm2>\r\n"
           b"Call-ID: foo\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
    resp = await udp_probe(ip, 5060, pkt, timeout=3)
    sip_responding = resp.startswith(b"SIP/2.0")
    ctx.state["sip_responding"] = sip_responding
    ctx.state["banner"] = resp[:200].decode("utf-8","ignore") if resp else ""
    ctx.source("SIP OPTIONS probe on UDP 5060")

RULES = [

]

@router.post("/api/recon/voip_sip_enum")
async def recon_voip_sip_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="voip_sip_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("SIP Responding","sip_responding"),("Banner","banner")])

def register(app):
    app.include_router(router)
