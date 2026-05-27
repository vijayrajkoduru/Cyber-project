"""tcp_port_scan — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_open, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip:
        ctx.state["unresolved"] = True; ctx.source("DNS resolution failed"); return
    TOP = [21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,873,993,995,
           1080,1194,1433,1521,1723,2049,2375,2376,2379,3306,3389,4444,5000,5432,5601,
           5672,5900,5984,6379,6443,7474,7687,8000,8008,8080,8081,8086,8088,8443,8888,
           9000,9042,9090,9092,9200,9300,9418,9999,10000,10250,11211,15672,27017,27018]
    sem = asyncio.Semaphore(40)
    async def _check(p):
        async with sem: return p if await tcp_open(ip, p, timeout=2) else None
    res = await asyncio.gather(*[_check(p) for p in TOP], return_exceptions=True)
    open_ports = sorted({p for p in res if isinstance(p,int)})
    ctx.state["ip"] = ip; ctx.state["open_ports"] = open_ports
    ctx.state["ports_scanned"] = len(TOP)
    ctx.source(f"TCP connect scan ({len(TOP)} common ports)")

RULES = [
    lambda s: {"name":"Dangerous service exposed (Telnet/FTP/RDP/SMB)","severity":"HIGH",
        "evidence":f"Open ports: {[p for p in s.get('open_ports',[]) if p in (21,23,135,139,445,3389)]}",
        "remediation":"Block legacy protocols at firewall. Use SSH+SFTP not Telnet/FTP. RDP via VPN only.",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if any(p in (21,23,135,139,445,3389) for p in s.get("open_ports",[])) else None,
    lambda s: {"name":"Database port exposed to internet","severity":"HIGH",
        "evidence":f"DB ports open: {[p for p in s.get('open_ports',[]) if p in (1433,3306,5432,6379,9200,11211,27017)]}",
        "remediation":"Firewall DB ports to internal network only. Require VPN/bastion.",
        "cwe":"CWE-668","owasp":"A05:2021"
    } if any(p in (1433,3306,5432,6379,9200,11211,27017) for p in s.get("open_ports",[])) else None,
]

@router.post("/api/recon/tcp_port_scan")
async def recon_tcp_port_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="tcp_port_scan",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("IP","ip"),("Open Ports","open_ports"),("Ports Scanned","ports_scanned")])

def register(app):
    app.include_router(router)
