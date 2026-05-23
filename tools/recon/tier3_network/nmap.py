"""Deep Port Scan — VL-FORGE pattern.

Route: /api/recon/nmap  (frontend tool key: "nmap")

Probes the top 1000 most common service ports via TCP connect.
Significantly slower than Fast Port Scan (~30 sec) but much wider
coverage. Same findings rules apply but on broader port surface.

Sources (parallel):
  1. TCP probe per port (1000 ports, batched to avoid resolver flooding)
  2. DNS resolution to IP
"""
import asyncio
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.portscan_findings import (
    PORTSCAN_FINDING_RULES, PORT_CATALOG,
)
from tools.recon._portscan_engine import tcp_probe, TOP_1000_PORTS

router = APIRouter()


async def gather(ctx: ScanContext):
    host = ctx.host
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # Top 1000 ports, batched 50 at a time to avoid socket exhaustion
    ports = TOP_1000_PORTS
    BATCH = 50
    open_ports_raw = []
    for i in range(0, len(ports), BATCH):
        chunk = ports[i:i+BATCH]
        results = await asyncio.gather(*[
            tcp_probe(ip, p, timeout=1.5) for p in chunk
        ])
        for port, is_open in zip(chunk, results):
            if is_open:
                open_ports_raw.append(port)

    # Annotate with catalog metadata where available
    open_ports = []
    for port in sorted(open_ports_raw):
        if port in PORT_CATALOG:
            svc, sev, cwe = PORT_CATALOG[port]
        else:
            svc, sev, cwe = "unknown", "INFO", None
        open_ports.append({"port": port, "service": svc, "severity": sev, "cwe": cwe})

    ctx.state["ports_open"] = open_ports
    ctx.state["ports_probed"] = len(ports)
    ctx.state["http_present"] = any(p["port"] in (80, 8080, 8000) for p in open_ports)
    ctx.state["https_present"] = any(p["port"] in (443, 8443) for p in open_ports)

    if ports:
        ctx.source(f"tcp-connect-top-{len(ports)}")

    ctx.state["ports"] = [{"port": p["port"], "proto": "tcp", "state": "open",
                            "service": p["service"]} for p in open_ports]


INTEL_FIELDS = [
    ("IP address",      "ip"),
    ("Ports probed",     "ports_probed"),
    ("Open ports",       "open_ports_display"),
    ("Scan engine",      "scan_engine_display"),
]


@router.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        op = ctx.state.get("ports_open") or []
        if op:
            ctx.state["open_ports_display"] = ", ".join(
                f"{p['port']}/{p['service']}" for p in op[:20])
        ctx.state["scan_engine_display"] = "Python asyncio TCP connect (top 1000)"

    return await run_scanner(
        host=host, tool="nmap",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ports", "ip", "ports_open"],
    )


def register(app):
    app.include_router(router)
