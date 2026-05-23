"""Shodan Lookup v2 — VL-FORGE pattern.

Route: /api/recon/shodan

Sources:
  1. DNS resolution to IP
  2. Shodan host API (/shodan/host/<ip>) — requires API key
  3. Vulnerability list extraction (if Shodan flagged CVEs)
"""
import asyncio
import socket

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.shodan_findings import SHODAN_FINDING_RULES

router = APIRouter()


def _shodan_host(ip, api_key):
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                          timeout=15, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


async def gather(ctx: ScanContext):
    host = ctx.host

    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # API key check — frontend passes via req.api_key
    api_key = ctx.state.get("api_key", "")  # populated via override below
    if not api_key:
        ctx.state["api_key_configured"] = False
        return

    ctx.state["api_key_configured"] = True
    data = await asyncio.to_thread(_shodan_host, ip, api_key)
    if not data:
        return
    ctx.source("shodan-host-api")

    ctx.state["shodan_host_data"] = True
    ctx.state["shodan_org"] = data.get("org")
    ctx.state["shodan_isp"] = data.get("isp")
    ctx.state["country"] = data.get("country_name")
    ctx.state["city"] = data.get("city")
    ctx.state["os"] = data.get("os")
    ctx.state["ports"] = data.get("ports", [])
    ctx.state["vulns"] = list(data.get("vulns") or [])
    if ctx.state["vulns"]:
        ctx.source("shodan-vuln-list")


INTEL_FIELDS = [
    ("IP",            "ip"),
    ("Shodan org",    "shodan_org"),
    ("ISP",           "shodan_isp"),
    ("Country",       "country"),
    ("City",          "city"),
    ("OS",             "os"),
    ("Open ports",   "ports_display"),
    ("CVEs flagged", "vulns_display"),
]


@router.post("/api/recon/shodan")
async def recon_shodan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        # Inject api_key from request before gather()
        ctx.state["api_key"] = getattr(req, "api_key", "") or ""
        await gather(ctx)
        ports = ctx.state.get("ports") or []
        if ports:
            ctx.state["ports_display"] = ", ".join(str(p) for p in ports[:20])
        v = ctx.state.get("vulns") or []
        if v:
            ctx.state["vulns_display"] = ", ".join(v[:10])

    return await run_scanner(
        host=host, tool="shodan",
        gather_func=gather_with_display,
        finding_rules=SHODAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ip", "ports", "vulns"],
    )


def register(app):
    app.include_router(router)
