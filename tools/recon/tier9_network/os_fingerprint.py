"""os_fingerprint — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_banner, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    # Heuristic: SSH banner often discloses OS, HTTP Server header too
    ssh = await tcp_banner(ip, 22, timeout=3)
    http = await tcp_banner(ip, 80, timeout=3, send=b"HEAD / HTTP/1.0\r\n\r\n")
    os_hints = []
    s = (ssh + http).decode("utf-8","ignore").lower()
    for marker, os_ in [("ubuntu","Ubuntu"),("debian","Debian"),("centos","CentOS"),("redhat","RHEL"),
                        ("amazon","Amazon Linux"),("alpine","Alpine"),("microsoft-iis","Windows Server"),
                        ("freebsd","FreeBSD")]:
        if marker in s: os_hints.append(os_)
    ctx.state["os_hints"] = sorted(set(os_hints))
    ctx.state["evidence"] = {"ssh": ssh[:120].decode("utf-8","ignore"), "http": http[:120].decode("utf-8","ignore")}
    ctx.source("Banner-based OS heuristic (no raw sockets)")

RULES = [

]

@router.post("/api/recon/os_fingerprint")
async def recon_os_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="os_fingerprint",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Os Hints","os_hints"),("Evidence","evidence")])

def register(app):
    app.include_router(router)
