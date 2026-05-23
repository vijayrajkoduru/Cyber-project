"""ASN / IP Ownership v2 — VL-FORGE pattern.

Route: /api/recon/asn

Sources (parallel):
  1. DNS resolution to IPv4/IPv6
  2. Team Cymru WHOIS for ASN (authoritative)
  3. ipinfo.io for org / country / city / region (free tier 50k/mo)
  4. Multi-IP -> multi-ASN detection (Anycast hint)
"""
import asyncio
import socket

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import (
    ScanContext, run_scanner, team_cymru_asn, dns_resolve,
)
from tools._payloads.asn_findings import ASN_FINDING_RULES

router = APIRouter()


async def _ipinfo(ip):
    def _do():
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}
    return await asyncio.to_thread(_do)


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["host"] = host

    # Resolve IP
    a_records = await dns_resolve(host, "A")
    if not a_records:
        return
    ip = a_records[0]
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # Parallel: Team Cymru + ipinfo + all A-record ASNs
    cymru_task = team_cymru_asn(ip)
    ipinfo_task = _ipinfo(ip)
    # Also resolve all unique IPs and get ASN for each (Anycast detection)
    other_ip_cymru_tasks = [team_cymru_asn(other_ip)
                              for other_ip in a_records[1:4]]

    cymru, ipinfo_data, *other_cymru = await asyncio.gather(
        cymru_task, ipinfo_task, *other_ip_cymru_tasks,
    )

    if cymru and cymru.get("asn"):
        ctx.source("team-cymru-asn")
        ctx.state["asn"] = cymru["asn"]
        # "info" looks like "AMAZON-AES, US"
        info = cymru.get("info") or ""
        ctx.state["org"] = info.split(",")[0].strip() if info else None
        ctx.state["country"] = cymru.get("country")
        ctx.state["bgp_prefix"] = cymru.get("bgp_prefix")

    if ipinfo_data:
        ctx.source("ipinfo.io")
        # Prefer ipinfo for org if Cymru didn't have it
        if not ctx.state.get("org"):
            ctx.state["org"] = ipinfo_data.get("org")
        if not ctx.state.get("country"):
            ctx.state["country"] = ipinfo_data.get("country")
        ctx.state["city"] = ipinfo_data.get("city")
        ctx.state["region"] = ipinfo_data.get("region")
        ctx.state["hostname"] = ipinfo_data.get("hostname")

    # Multi-ASN check (Anycast / CDN signal)
    asns_seen = {ctx.state.get("asn")}
    for other in other_cymru:
        if other.get("asn"):
            asns_seen.add(other["asn"])
    asns_seen.discard(None)
    if len(asns_seen) > 1:
        ctx.state["multiple_asns"] = sorted(asns_seen)
        ctx.source("multi-asn-detection")

    ctx.state["resolved_ips"] = a_records


INTEL_FIELDS = [
    ("Target",       "host"),
    ("Resolved IP",  "ip"),
    ("All IPs",      "resolved_ips_display"),
    ("ASN",          "asn"),
    ("Organization", "org"),
    ("BGP prefix",   "bgp_prefix"),
    ("Country",       "country"),
    ("Region",        "region"),
    ("City",          "city"),
    ("Reverse DNS",   "hostname"),
    ("Multiple ASNs (Anycast)", "multi_asn_display"),
]


@router.post("/api/recon/asn")
async def recon_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ips = ctx.state.get("resolved_ips") or []
        if len(ips) > 1: ctx.state["resolved_ips_display"] = ", ".join(ips)
        masns = ctx.state.get("multiple_asns") or []
        if masns: ctx.state["multi_asn_display"] = ", ".join(masns)

    return await run_scanner(
        host=host, tool="asn",
        gather_func=gather_with_display,
        finding_rules=ASN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ip", "asn", "country", "org", "bgp_prefix",
                          "region", "city", "hostname"],
    )


def register(app):
    app.include_router(router)
