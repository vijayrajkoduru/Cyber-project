"""Banner Grabbing — VL-FORGE pattern.

Route: /api/recon/banner  (frontend tool key: "banner")

Connects to each open port and reads the first bytes of response —
service greeting banner. Banners often reveal product + version,
useful for CVE matching downstream.

Sources (parallel):
  1. TCP probe top-40 ports
  2. Banner grab per open port (with HTTP-style probe for web ports)
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

    banner_results = await asyncio.gather(*[
        grab_banner(ip, p, timeout=3.0) for p in open_ports
    ])

    banners = {}
    versions = {}
    ports_data = []
    for port, banner in zip(open_ports, banner_results):
        clean = (banner or "").strip()
        if clean:
            banners[port] = clean[:300]
            ver = parse_version_from_banner(clean)
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
    ctx.state["http_present"] = any(p in (80, 8080, 8000) for p in open_ports)
    ctx.state["https_present"] = any(p in (443, 8443) for p in open_ports)

    if banners:
        ctx.source(f"banner-extract-{len(banners)}")

    # Backwards-compat — frontend isEmpty checks Object.keys(d.banners).length
    # Build dict version too
    ctx.state["ports"] = [{"port": p["port"], "service": p["service"],
                            "banner": p.get("banner")} for p in ports_data]


INTEL_FIELDS = [
    ("IP address",      "ip"),
    ("Ports probed",     "ports_probed"),
    ("Banners captured", "banner_count_display"),
    ("Sample banner",    "banner_sample_display"),
]


@router.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        banners = ctx.state.get("banners") or {}
        if banners:
            ctx.state["banner_count_display"] = (
                f"{len(banners)} banner(s) captured")
            sample = next(iter(banners.items()))
            ctx.state["banner_sample_display"] = (
                f"port {sample[0]}: {sample[1][:100]}"
                + ("..." if len(sample[1]) > 100 else ""))

    return await run_scanner(
        host=host, tool="banner",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["banners", "ip", "ports", "versions"],
    )


def register(app):
    app.include_router(router)
