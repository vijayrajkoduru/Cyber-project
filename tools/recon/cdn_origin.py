"""CDN Origin Discovery v2 — VL-FORGE pattern.

Route: /api/recon/cdn_origin

Sources (parallel):
  1. Apex IP resolution + CDN family check
  2. MX-record probe (mail often leaks origin)
  3. Common bypass-subdomain probe (mail/ftp/cpanel/direct/origin)
  4. Reverse-DNS hint per resolved IP
"""
import asyncio
import re
import socket

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner, dns_resolve
from tools._payloads.cdn_origin_findings import CDN_ORIGIN_FINDING_RULES

router = APIRouter()


# CDN IP-range fingerprints
_CDN_RANGES = {
    "Cloudflare":  [r"^104\.(1[6-9]|2[0-9]|3[01])\.", r"^172\.(6[4-9]|7[0-9])\.",
                    r"^173\.245\.4[8-9]\.", r"^141\.101\."],
    "Akamai":      [r"^23\.(3[2-9]|[4-9][0-9])\.", r"^2\.(1[6-9]|2[0-9])\."],
    "Fastly":      [r"^151\.101\."],
    "CloudFront":  [r"^13\.(2[2-3][0-9]|2[4-9][0-9])\.", r"^54\.[1-2][0-9][0-9]\."],
}


# Common subdomains that often skip CDN
_BYPASS_PREFIXES = [
    "mail", "smtp", "imap", "pop", "webmail", "email",
    "ftp", "sftp", "ssh",
    "cpanel", "webdisk", "whm",
    "direct", "origin", "real",
    "test", "staging", "dev",
    "api", "internal",
]


def _identify_cdn(ip):
    for cdn, patterns in _CDN_RANGES.items():
        if any(re.match(p, str(ip)) for p in patterns):
            return cdn
    return None


async def _resolve_subdomain(host, sub):
    full = f"{sub}.{host}"
    ips = await dns_resolve(full, "A")
    return full, ips[0] if ips else None


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["host"] = host

    # Apex IP resolution
    apex_ips = await dns_resolve(host, "A")
    if not apex_ips:
        return
    ctx.state["apex_ips"] = apex_ips
    ctx.source("dns-resolve")

    # CDN detection from apex IP
    cdn = None
    for ip in apex_ips:
        c = _identify_cdn(ip)
        if c:
            cdn = c
            break
    ctx.state["cdn_detected"] = cdn

    methods_tried = []
    origin_candidates = []

    # 1. MX records — mail server often on origin host
    mx_records = await dns_resolve(host, "MX")
    methods_tried.append("mx-record-probe")
    if mx_records:
        ctx.source("mx-probe")
        for mx in mx_records[:3]:
            # MX format: "10 mail.example.com" — extract hostname
            parts = str(mx).split()
            mx_host = parts[-1].rstrip(".") if parts else None
            if not mx_host: continue
            mx_ips = await dns_resolve(mx_host, "A")
            for mip in mx_ips:
                # If MX IP is NOT in CDN range, it may be origin leak
                if cdn and not _identify_cdn(mip):
                    ctx.state["mx_leak"] = f"{mx_host} -> {mip}"
                    origin_candidates.append({
                        "ip": mip, "method": f"MX ({mx_host})",
                    })

    # 2. Bypass-subdomain probes
    methods_tried.append("bypass-subdomain-probe")
    sub_tasks = [_resolve_subdomain(host, sub) for sub in _BYPASS_PREFIXES]
    sub_results = await asyncio.gather(*sub_tasks)
    subdomain_leaks = []
    for full, ip in sub_results:
        if not ip: continue
        # If subdomain resolves to non-CDN IP, candidate origin leak
        if cdn and not _identify_cdn(ip):
            subdomain_leaks.append({"subdomain": full, "ip": ip})
            origin_candidates.append({"ip": ip, "method": f"subdomain ({full})"})
    if subdomain_leaks:
        ctx.source(f"bypass-subdomain-{len(subdomain_leaks)}-leaks")
    ctx.state["subdomain_leaks"] = subdomain_leaks

    # 3. Reverse-DNS hint per apex IP (sometimes points to original host)
    methods_tried.append("reverse-dns-probe")

    # Deduplicate origin candidates by IP
    seen_ips = set()
    unique_candidates = []
    for c in origin_candidates:
        if c["ip"] in seen_ips: continue
        seen_ips.add(c["ip"])
        unique_candidates.append(c)
    ctx.state["origin_candidates"] = unique_candidates
    ctx.state["methods_tried"] = methods_tried

    # Backwards-compat for frontend isEmpty (cdn_detected[])
    ctx.state["cdn_detected_list"] = [cdn] if cdn else []


INTEL_FIELDS = [
    ("Target",                    "host"),
    ("CDN in front",              "cdn_detected"),
    ("Apex IPs",                   "apex_ips_display"),
    ("MX leak",                    "mx_leak"),
    ("Subdomain leaks",           "subdomain_leaks_display"),
    ("Origin candidates",         "origin_candidates_display"),
    ("Methods tried",              "methods_display"),
]


@router.post("/api/recon/cdn_origin")
async def recon_cdn_origin(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ai = ctx.state.get("apex_ips") or []
        if ai: ctx.state["apex_ips_display"] = ", ".join(ai)
        sl = ctx.state.get("subdomain_leaks") or []
        if sl: ctx.state["subdomain_leaks_display"] = "; ".join(
            f"{x['subdomain']} -> {x['ip']}" for x in sl[:5])
        oc = ctx.state.get("origin_candidates") or []
        if oc: ctx.state["origin_candidates_display"] = "; ".join(
            f"{c['ip']} ({c['method']})" for c in oc[:5])
        mt = ctx.state.get("methods_tried") or []
        if mt: ctx.state["methods_display"] = ", ".join(mt)

    return await run_scanner(
        host=host, tool="cdn_origin",
        gather_func=gather_with_display,
        finding_rules=CDN_ORIGIN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["cdn_detected_list", "origin_candidates"],
    )


def register(app):
    app.include_router(router)
