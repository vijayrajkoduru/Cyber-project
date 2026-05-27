"""snmp_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import udp_probe, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    # SNMPv2c GET with "public" community
    pkt = bytes.fromhex("302602010004067075626c6963a0190204000000000201000201003008300906052b0601020105")
    resp = await udp_probe(ip, 161, pkt, timeout=3)
    public_works = bool(resp and len(resp) > 10)
    ctx.state["snmp_public_community"] = public_works
    ctx.source("SNMPv2c GET with community=public")

RULES = [
    lambda s: {"name":"SNMP Default Community 'public' Accessible","severity":"HIGH",
        "evidence":"SNMP responded to community 'public' — information disclosure (interfaces, processes, configs)",
        "remediation":"Change SNMP community string; restrict 161/udp to monitoring servers only; prefer SNMPv3 with auth+priv",
        "cwe":"CWE-1188","owasp":"A05:2021"
    } if s.get("snmp_public_community") else None,
]

@router.post("/api/recon/snmp_enum")
async def recon_snmp_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="snmp_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("SNMP Public Community","snmp_public_community")])

def register(app):
    app.include_router(router)
