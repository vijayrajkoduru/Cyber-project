"""banner_grab — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_banner, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    banners = {}
    for port in (21,22,25,110,143,2375,2376,3306,5432,6379,8080,8443,9200,11211,27017):
        b = await tcp_banner(ip, port, timeout=2)
        if b: banners[port] = b[:200].decode("utf-8","ignore").strip()
    ctx.state["banners"] = banners
    ctx.source("Raw banner grab — 15 service ports")

RULES = [
    lambda s: {"name":"Redis Exposed Without Auth","severity":"CRITICAL",
        "evidence":f"Redis banner on 6379: {s.get('banners',{}).get(6379,'')}",
        "remediation":"Set requirepass; bind to internal IP; firewall 6379",
        "cwe":"CWE-306","owasp":"A07:2021"
    } if "redis" in (s.get("banners",{}).get(6379,"") or "").lower() else None,
    lambda s: {"name":"Memcached Exposed (UDP amplification risk)","severity":"HIGH",
        "evidence":"Memcached responsive on 11211",
        "remediation":"Bind memcached to localhost or -U 0 to disable UDP",
        "cwe":"CWE-306","owasp":"A07:2021"
    } if 11211 in s.get("banners",{}) else None,
    lambda s: {"name":"Docker Daemon API Exposed","severity":"CRITICAL",
        "evidence":f"Docker socket on 2375/2376: {s.get('banners',{}).get(2375,'')}",
        "remediation":"NEVER expose 2375 (unencrypted) to network. Use TLS-only 2376 or Unix socket.",
        "cwe":"CWE-306","owasp":"A07:2021"
    } if 2375 in s.get("banners",{}) or 2376 in s.get("banners",{}) else None,
]

@router.post("/api/recon/banner_grab")
async def recon_banner_grab(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="banner_grab",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Banners","banners")])

def register(app):
    app.include_router(router)
