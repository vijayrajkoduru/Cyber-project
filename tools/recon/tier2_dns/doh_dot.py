"""doh_dot — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import socket, ssl, urllib.request

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    ns_list = await resolve_ns(h)
    doh_ok = dot_ok = False
    for ns in ns_list[:3]:
        # DoT — TCP 853 TLS handshake
        try:
            def _dot():
                ctxt = ssl.create_default_context()
                with socket.create_connection((ns, 853), timeout=4) as s:
                    with ctxt.wrap_socket(s, server_hostname=ns) as ss:
                        return True
            if await asyncio.to_thread(_dot): dot_ok = True
        except Exception: pass
        # DoH — try https://ns/dns-query
        try:
            def _doh():
                req = urllib.request.Request(f"https://{ns}/dns-query?name=example.com&type=A",
                    headers={"Accept":"application/dns-json"})
                with urllib.request.urlopen(req, timeout=4) as r:
                    return r.status == 200
            if await asyncio.to_thread(_doh): doh_ok = True
        except Exception: pass
    ctx.state["doh_supported"] = doh_ok
    ctx.state["dot_supported"] = dot_ok
    ctx.source("DoH (HTTPS) + DoT (TLS 853) probes")

RULES = [
    # Intel-only, no findings (DoH/DoT absence isn't a vuln)

]

@router.post("/api/recon/doh_dot")
async def recon_doh_dot(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="doh_dot",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("DoH Supported","doh_supported"),("DoT Supported","dot_supported")])

def register(app):
    app.include_router(router)
