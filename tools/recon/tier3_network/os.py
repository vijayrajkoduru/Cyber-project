"""OS Fingerprinting — VL-FORGE pattern.

Route: /api/recon/os  (frontend tool key: "os")

Pure-Python OS inference (no nmap binary required):
  1. Banner-based OS hints (Ubuntu/Debian/CentOS/Windows/etc.)
  2. Common-port pattern analysis (Windows-specific ports 135/445/3389
     vs Unix-specific 22/SSH)
  3. TTL hint via socket connection (limited without raw sockets)

Less accurate than `nmap -O` (which needs raw socket privileges) but
works on any host without root.
"""
import asyncio
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.portscan_findings import (
    PORTSCAN_FINDING_RULES, PORT_CATALOG,
)
from tools._framework.portscan_engine import (
    tcp_probe, grab_banner, os_hint_from_banner, os_fingerprint_probe,
)

router = APIRouter()

# Ports that hint at an OS family (presence ≠ proof, but a signal)
_WINDOWS_PORTS = {135, 137, 138, 139, 445, 3389, 5985, 5986}
_UNIX_PORTS = {22, 111, 514, 873, 2049}
_MAC_PORTS = {548, 631, 5353}


async def gather(ctx: ScanContext):
    host = ctx.host
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # Probe a SUBSET of ports relevant to OS detection — fast
    probe_ports = sorted(set(_WINDOWS_PORTS | _UNIX_PORTS | _MAC_PORTS |
                              {80, 443, 8080, 8443, 22, 25}))
    probe_results = await asyncio.gather(*[
        tcp_probe(ip, p, timeout=1.5) for p in probe_ports
    ])
    open_ports_set = {p for p, ok in zip(probe_ports, probe_results) if ok}

    if open_ports_set:
        ctx.source(f"port-pattern-probe-{len(probe_ports)}")

    # Score OS families by port presence
    scores = {
        "Windows": len(_WINDOWS_PORTS & open_ports_set),
        "Linux/Unix": len(_UNIX_PORTS & open_ports_set),
        "macOS": len(_MAC_PORTS & open_ports_set),
    }
    best_family = max(scores.items(), key=lambda kv: kv[1])
    os_family_hint = best_family[0] if best_family[1] > 0 else None

    # Try banner-based OS detection on web/SSH ports
    banner_ports = [p for p in (80, 443, 8080, 22, 25) if p in open_ports_set]
    if banner_ports:
        banners = await asyncio.gather(*[
            grab_banner(ip, p, timeout=3.0) for p in banner_ports
        ])
        for banner in banners:
            hint = os_hint_from_banner(banner)
            if hint:
                ctx.state["os_hint"] = hint
                ctx.source("banner-os-inference")
                break

    # Fallback to port-family hint if no banner hint
    if not ctx.state.get("os_hint") and os_family_hint:
        ctx.state["os_hint"] = f"{os_family_hint} (port-pattern hint)"

    # TTL probe (limited — needs raw sockets for accuracy)
    fp = await asyncio.to_thread(os_fingerprint_probe, host)
    if fp.get("window_size"):
        ctx.state["window_size"] = fp["window_size"]

    # Annotate open ports for the shared findings rules
    open_ports_data = []
    for port in sorted(open_ports_set):
        svc, sev, cwe = PORT_CATALOG.get(port, ("unknown", "INFO", None))
        open_ports_data.append({"port": port, "service": svc,
                                 "severity": sev, "cwe": cwe})
    ctx.state["ports_open"] = open_ports_data
    ctx.state["ports_probed"] = len(probe_ports)
    ctx.state["http_present"] = 80 in open_ports_set or 8080 in open_ports_set
    ctx.state["https_present"] = 443 in open_ports_set or 8443 in open_ports_set

    # Backwards-compat — frontend isEmpty checks !d.os && !d.os_match
    if ctx.state.get("os_hint"):
        ctx.state["os"] = ctx.state["os_hint"]
        ctx.state["os_match"] = ctx.state["os_hint"]


INTEL_FIELDS = [
    ("IP address",          "ip"),
    ("OS hint",              "os_hint"),
    ("TCP window size",     "window_size"),
    ("Open OS-indicator ports", "open_ports_display"),
]


@router.post("/api/recon/os")
async def recon_os(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        op = ctx.state.get("ports_open") or []
        if op:
            ctx.state["open_ports_display"] = ", ".join(
                f"{p['port']}/{p['service']}" for p in op[:10])

    return await run_scanner(
        host=host, tool="os",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["os", "os_match", "ip", "ports_open"],
    )


def register(app):
    app.include_router(router)
