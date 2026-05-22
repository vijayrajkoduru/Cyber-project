"""Free Shodan / InternetDB v2 — VL-FORGE pattern.

Route: /api/recon/internetdb

Sources:
  1. DNS resolution to IP
  2. Shodan InternetDB free API (https://internetdb.shodan.io/<ip>)
     — no API key required, returns ports / CVEs / hostnames / tags
"""
import asyncio
import socket

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.internetdb_findings import INTERNETDB_FINDING_RULES

router = APIRouter()


def _query_internetdb(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}",
                          timeout=10, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


async def gather(ctx: ScanContext):
    host = ctx.host
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    data = await asyncio.to_thread(_query_internetdb, ip)
    if not data:
        ctx.state["found"] = False
        return

    ctx.source("shodan-internetdb-free")
    ctx.state["found"] = True
    ctx.state["ports"] = data.get("ports", [])
    ctx.state["cves"] = data.get("vulns", [])
    ctx.state["hostnames"] = data.get("hostnames", [])
    ctx.state["tags"] = data.get("tags", [])


INTEL_FIELDS = [
    ("IP",          "ip"),
    ("In Shodan",   "found"),
    ("Open ports", "ports_display"),
    ("CVEs",        "cves_display"),
    ("Hostnames",   "hostnames_display"),
    ("Tags",        "tags_display"),
]


@router.post("/api/recon/internetdb")
async def recon_internetdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        p = ctx.state.get("ports") or []
        if p: ctx.state["ports_display"] = ", ".join(str(x) for x in p[:15])
        c = ctx.state.get("cves") or []
        if c: ctx.state["cves_display"] = ", ".join(c[:8])
        h = ctx.state.get("hostnames") or []
        if h: ctx.state["hostnames_display"] = ", ".join(h[:5])
        t = ctx.state.get("tags") or []
        if t: ctx.state["tags_display"] = ", ".join(t)

    return await run_scanner(
        host=host, tool="internetdb",
        gather_func=gather_with_display,
        finding_rules=INTERNETDB_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["found", "ports", "vulns"],
    )


def register(app):
    app.include_router(router)
