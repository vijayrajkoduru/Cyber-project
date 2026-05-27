"""smb_netbios_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_open, tcp_banner, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    smb_445 = await tcp_open(ip, 445, timeout=3)
    nb_139  = await tcp_open(ip, 139, timeout=3)
    ctx.state["smb_445_open"] = smb_445
    ctx.state["netbios_139_open"] = nb_139
    ctx.source("SMB/NetBIOS TCP port probe")

RULES = [
    lambda s: {"name":"SMB Port Exposed to Internet","severity":"HIGH",
        "evidence":"TCP 445 reachable — SMB historically critical (WannaCry/EternalBlue)",
        "remediation":"Block 139/445 at perimeter firewall. SMB should never be internet-facing.",
        "cwe":"CWE-668","owasp":"A05:2021"
    } if s.get("smb_445_open") or s.get("netbios_139_open") else None,
]

@router.post("/api/recon/smb_netbios_enum")
async def recon_smb_netbios_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="smb_netbios_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("SMB 445 Open","smb_445_open"),("Netbios 139 Open","netbios_139_open")])

def register(app):
    app.include_router(router)
