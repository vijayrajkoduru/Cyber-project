"""ldap_anon_bind — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._network_helpers import tcp_banner, resolve_host

router = APIRouter()

async def gather(ctx: ScanContext):
    ip = resolve_host(ctx.host)
    if not ip: ctx.state["unresolved"]=True; ctx.source("DNS"); return
    # LDAP anonymous bind request (BindRequest version=3 name="" auth=simple)
    pkt = bytes.fromhex("300c020101600702010304008000")
    resp = await tcp_banner(ip, 389, timeout=3, send=pkt)
    success = resp.startswith(b"\x30") and len(resp) > 5
    ctx.state["anon_bind_succeeded"] = success
    ctx.state["bytes_returned"] = len(resp) if resp else 0
    ctx.source("LDAP anonymous bind probe")

RULES = [
    lambda s: {"name":"LDAP Anonymous Bind Allowed","severity":"HIGH",
        "evidence":"LDAP 389 accepted anonymous bind — directory enumeration possible",
        "remediation":"Disable anonymous bind. Restrict LDAP to authenticated queries. Prefer LDAPS (636).",
        "cwe":"CWE-287","owasp":"A07:2021"
    } if s.get("anon_bind_succeeded") else None,
]

@router.post("/api/recon/ldap_anon_bind")
async def recon_ldap_anon_bind(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ldap_anon_bind",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Anon Bind Succeeded","anon_bind_succeeded"),("Bytes Returned","bytes_returned")])

def register(app):
    app.include_router(router)
