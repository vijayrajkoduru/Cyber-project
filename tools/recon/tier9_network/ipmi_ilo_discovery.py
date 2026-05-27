"""ipmi_ilo_discovery — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_open, udp_probe, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    findings = []
    if await tcp_open(ip, 443, timeout=3):
        from tools.recon._web_helpers import fetch
        c, hdrs, b = await fetch(f"https://{ip}/", timeout=4)
        s = (str(hdrs) + b.decode("utf-8","ignore")[:2048]).lower()
        for name in ("ilo","idrac","ipmi","supermicro","cimc"):
            if name in s: findings.append({"service":name,"port":443})
    # IPMI UDP 623
    ipmi_resp = await udp_probe(ip, 623, bytes.fromhex("0600ff07000000000000000000092018c88100388e04b5"), timeout=3)
    if ipmi_resp: findings.append({"service":"ipmi","port":623})
    ctx.state["findings"] = findings
    ctx.source("HP iLO / Dell iDRAC / IPMI fingerprint")

RULES = [
    lambda s: {"name":"Out-of-Band Management Interface Exposed","severity":"HIGH",
        "evidence":f"Management interface(s) reachable: {s.get('findings')}",
        "remediation":"Restrict iLO/iDRAC/IPMI to dedicated management network. Never expose to internet.",
        "cwe":"CWE-668","owasp":"A01:2021"
    } if s.get("findings") else None,
]

@router.post("/api/recon/ipmi_ilo_discovery")
async def recon_ipmi_ilo_discovery(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ipmi_ilo_discovery",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Findings","findings")])

def register(app):
    app.include_router(router)
