"""rpc_endpoint_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_open, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    rpc_open = await tcp_open(ip, 135, timeout=3)
    ctx.state["rpc_135_open"] = rpc_open
    ctx.source("RPC Endpoint Mapper TCP 135 probe")

RULES = [
    lambda s: {"name":"RPC Endpoint Mapper Exposed","severity":"MEDIUM",
        "evidence":"TCP 135 reachable — Windows RPC enumeration possible",
        "remediation":"Block TCP 135 at firewall. Use IPSec or RPC over HTTPS if remote RPC needed.",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if s.get("rpc_135_open") else None,
]

@router.post("/api/recon/rpc_endpoint_enum")
async def recon_rpc_endpoint_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="rpc_endpoint_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("RPC 135 Open","rpc_135_open")])

def register(app):
    app.include_router(router)
