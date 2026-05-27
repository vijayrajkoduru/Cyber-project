"""mx_enum — VL-FORGE Recon §2 DNS Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._dns_helpers import query, resolve_ns, query_at
import socket

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    mx = await query(h, "MX")
    hosts = []
    for line in mx:
        parts = line.split()
        if len(parts) >= 2:
            hosts.append(parts[1].rstrip("."))
    mx_intel = []
    for mh in hosts:
        ips = await query(mh, "A")
        # SMTP banner probe (port 25 → close immediately)
        smtp_open = False
        if ips:
            def _probe():
                try:
                    with socket.create_connection((ips[0], 25), timeout=3) as s:
                        return True
                except Exception:
                    return False
            smtp_open = await asyncio.to_thread(_probe)
        mx_intel.append({"host": mh, "ips": ips, "smtp_open": smtp_open})
    ctx.state["mx_hosts"] = hosts
    ctx.state["mx_intel"] = mx_intel
    ctx.source("MX records + A resolution + SMTP probe")

RULES = [
    # Intel-only; finding only if no MX at all (covered in dns_records)

]

@router.post("/api/recon/mx_enum")
async def recon_mx_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="mx_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("MX Hosts","mx_hosts"),("MX Intel","mx_intel")])

def register(app):
    app.include_router(router)
