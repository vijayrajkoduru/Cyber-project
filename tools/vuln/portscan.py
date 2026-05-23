"""Fast Port Scan — VL-FORGE pattern.

Route: /api/recon/masscan  (frontend tool key: "masscan")

Probes the top 40 most security-relevant ports via TCP connect.
Faster than Deep Port Scan (~5 sec vs ~30 sec). Returns named findings
covering: databases exposed, admin ports exposed, DevOps panels, file-
shares, cleartext legacy protocols.

Sources (parallel):
  1. TCP probe per port (~40 in parallel)
  2. DNS resolution to IP

Findings (~12 rules from tools/_payloads/portscan_findings.py):
  CRITICAL: databases exposed
  HIGH    : admin ports exposed, DevOps panels, file-shares, legacy cleartext
  MEDIUM  : HTTP without HTTPS
  POSITIVE: HTTPS available, no ports open (filtered)
  INFO    : total open count
"""
import asyncio
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.portscan_findings import (
    PORTSCAN_FINDING_RULES, PORT_CATALOG,
)
from tools.recon._portscan_engine import tcp_probe

router = APIRouter()


async def gather(ctx: ScanContext):
    host = ctx.host

    # Resolve to IP
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # Probe the top ~40 catalog ports in parallel
    ports = sorted(PORT_CATALOG.keys())
    results = await asyncio.gather(*[tcp_probe(ip, p, timeout=2.0) for p in ports])
    open_ports = []
    for port, is_open in zip(ports, results):
        if not is_open: continue
        svc, sev, cwe = PORT_CATALOG[port]
        open_ports.append({"port": port, "service": svc, "severity": sev, "cwe": cwe})

    ctx.state["ports_open"] = open_ports
    ctx.state["ports_probed"] = len(ports)
    ctx.state["http_present"] = any(p["port"] in (80, 8080, 8000) for p in open_ports)
    ctx.state["https_present"] = any(p["port"] in (443, 8443) for p in open_ports)

    if ports:
        ctx.source(f"tcp-connect-{len(ports)}-ports")

    # Backwards-compat: top-level ports[] list for existing PDF section
    ctx.state["ports"] = [{"port": p["port"], "proto": "tcp", "state": "open",
                            "service": p["service"]} for p in open_ports]


INTEL_FIELDS = [
    ("IP address",          "ip"),
    ("Ports probed",         "ports_probed"),
    ("Open ports",           "open_ports_display"),
    ("HTTP / HTTPS",         "http_https_display"),
]


@router.post("/api/vuln/masscan")
async def recon_masscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        op = ctx.state.get("ports_open") or []
        if op:
            ctx.state["open_ports_display"] = ", ".join(
                f"{p['port']}/{p['service']}" for p in op[:10])
        ctx.state["http_https_display"] = (
            f"HTTP={ctx.state.get('http_present')}, "
            f"HTTPS={ctx.state.get('https_present')}")

    return await run_scanner(
        host=host, tool="masscan",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ports", "ip", "ports_open"],
    )


# Also register under /api/scan/portscan for legacy callers
@router.post("/api/scan/portscan")
async def legacy_scan_portscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await recon_masscan(req, _)


def register(app):
    app.include_router(router)
