"""Service Detection — VL-FORGE pattern.

Route: /api/recon/services  (frontend tool key: "services")

Identifies service VERSIONS on open ports via banner grabbing +
signature matching. Pure-Python equivalent of nmap -sV.

Sources (parallel):
  1. TCP probe top-40 ports
  2. Banner grab + version-pattern extraction per open port
"""
import asyncio
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.portscan_findings import (
    PORTSCAN_FINDING_RULES, PORT_CATALOG,
)
from tools.recon._portscan_engine import (
    tcp_probe, grab_banner, parse_version_from_banner,
)

router = APIRouter()


async def gather(ctx: ScanContext):
    host = ctx.host
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    ports = sorted(PORT_CATALOG.keys())
    probe_results = await asyncio.gather(*[tcp_probe(ip, p, timeout=2.0) for p in ports])
    open_ports = [p for p, ok in zip(ports, probe_results) if ok]

    if open_ports:
        ctx.source(f"tcp-probe-{len(ports)}")

    # Grab banners + parse versions in parallel
    banner_results = await asyncio.gather(*[
        grab_banner(ip, p, timeout=3.0) for p in open_ports
    ])

    banners, versions, ports_data = {}, {}, []
    for port, banner in zip(open_ports, banner_results):
        if banner:
            banners[port] = banner[:200]
            ver = parse_version_from_banner(banner)
            if ver:
                versions[port] = ver
        svc, sev, cwe = PORT_CATALOG.get(port, ("unknown", "INFO", None))
        ports_data.append({
            "port": port, "service": svc, "severity": sev, "cwe": cwe,
            "banner": banners.get(port), "version": versions.get(port),
        })

    ctx.state["ports_open"] = ports_data
    ctx.state["ports_probed"] = len(ports)
    ctx.state["banners"] = banners
    ctx.state["versions"] = versions
    ctx.state["http_present"] = any(p["port"] in (80, 8080, 8000) for p in ports_data)
    ctx.state["https_present"] = any(p["port"] in (443, 8443) for p in ports_data)

    if banners: ctx.source(f"banner-grab-{len(banners)}")
    if versions: ctx.source(f"version-extract-{len(versions)}")

    ctx.state["ports"] = [{"port": p["port"], "service": p["service"],
                            "version": p.get("version"), "banner": p.get("banner")}
                          for p in ports_data]


INTEL_FIELDS = [
    ("IP address",       "ip"),
    ("Open ports",        "open_ports_display"),
    ("Versions detected", "versions_display"),
    ("Banner samples",    "banners_display"),
]


@router.post("/api/vuln/service_detect")
async def recon_services(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        op = ctx.state.get("ports_open") or []
        if op:
            ctx.state["open_ports_display"] = ", ".join(
                f"{p['port']}/{p['service']}" for p in op[:10])
        versions = ctx.state.get("versions") or {}
        if versions:
            ctx.state["versions_display"] = "; ".join(
                f"{p}: {v}" for p, v in list(versions.items())[:6])
        banners = ctx.state.get("banners") or {}
        if banners:
            sample = next(iter(banners.items()))
            ctx.state["banners_display"] = (
                f"port {sample[0]}: {sample[1][:80]}"
                + (f" (+ {len(banners)-1} more)" if len(banners) > 1 else ""))

    return await run_scanner(
        host=host, tool="services",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ports", "ip", "versions", "banners"],
    )


def register(app):
    app.include_router(router)
