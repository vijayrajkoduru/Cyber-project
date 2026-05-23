"""recon_amass -- isolated tool (Kali-style architecture).

Route: /api/recon/amass
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

_BRUTE_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","admin",
    "blog","shop","store","api","api-dev","api-staging","api-prod",
    "app","apps","dev","test","staging","stage","beta","alpha",
    "preview","demo","qa","uat","sandbox",
    "cdn","static","assets","media","img","images","files","uploads",
    "secure","ssl","vpn","git","gitlab","jenkins",
    "ci","monitor","grafana","kibana","prometheus",
    "db","database","mysql","postgres","mongo",
    "backup","old","new","v1","v2","v3","internal",
    "support","help","docs","wiki","portal","dashboard",
    "auth","sso","login","account",
    "cpanel","panel","phpmyadmin",
    "mobile","m",
    "ns1","ns2","ns3","ns4","mx","mx1","mx2",
]

async def _resolve_brute(host, prefix):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        await resolver.resolve(f"{prefix}.{host}", "A")
        return f"{prefix}.{host}"
    except Exception:
        return None

async def _recon_amass_impl(req: ScanRequest, _=None):
    host = recon_host(req.target)
    all_subs = set()
    sources_hit = {}
    sources_failed = {}

    def _add_subs(names, source):
        before = len(all_subs)
        for name in names:
            name = str(name).strip().lower().lstrip("*.")
            if name and name.endswith(host) and not name.startswith("*"):
                all_subs.add(name)
        sources_hit[source] = len(all_subs) - before

    # 1. crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = []
            for e in r.json():
                names.extend(str(e.get("name_value", "")).split("\n"))
            _add_subs(names, "crt.sh")
    except Exception as e:
        sources_failed["crt.sh"] = str(e)[:80]

    # 2. CertSpotter
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={host}&include_subdomains=true&expand=dns_names",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = []
            for e in r.json():
                names.extend(e.get("dns_names", []))
            _add_subs(names, "certspotter")
    except Exception as e:
        sources_failed["certspotter"] = str(e)[:80]

    # 3. JLDC / Anubis
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{host}", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            _add_subs(r.json(), "jldc_anubis")
    except Exception as e:
        sources_failed["jldc_anubis"] = str(e)[:80]

    # 4. AlienVault OTX
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/passive_dns",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            names = [e.get("hostname", "") for e in r.json().get("passive_dns", [])]
            _add_subs(names, "alienvault_otx")
    except Exception as e:
        sources_failed["alienvault_otx"] = str(e)[:80]

    # 5. HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200 and "API count exceeded" not in r.text:
            names = [line.split(",")[0] for line in r.text.splitlines()]
            _add_subs(names, "hackertarget")
        elif "API count exceeded" in (r.text or ""):
            sources_failed["hackertarget"] = "rate limit"
    except Exception as e:
        sources_failed["hackertarget"] = str(e)[:80]

    # 6. RapidDNS (HTML parse)
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{host}?full=1", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            import re as _re
            esc_host = _re.escape(host)
            names = _re.findall(r"<td>([a-z0-9.-]+\." + esc_host + r")</td>", r.text.lower())
            _add_subs(names, "rapiddns")
    except Exception as e:
        sources_failed["rapiddns"] = str(e)[:80]

    # 7. ThreatCrowd passive DNS
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={host}",
                         timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            try:
                data = r.json()
                _add_subs(data.get("subdomains", []), "threatcrowd")
            except Exception:
                pass
    except Exception as e:
        sources_failed["threatcrowd"] = str(e)[:80]

    # 8. URLScan.io passive search
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100",
                         timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            try:
                data = r.json()
                hosts = set()
                for item in data.get("results", []):
                    page_host = item.get("page", {}).get("domain", "")
                    if page_host and page_host.endswith(host):
                        hosts.add(page_host.lower())
                _add_subs(hosts, "urlscan_io")
            except Exception:
                pass
    except Exception as e:
        sources_failed["urlscan_io"] = str(e)[:80]

    # 9. ShrewdEye (passive DNS aggregator)
    try:
        r = requests.get(f"https://shrewdeye.app/domains/{host}.txt", timeout=10,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            _add_subs(r.text.splitlines(), "shrewdeye")
    except Exception as e:
        sources_failed["shrewdeye"] = str(e)[:80]

    # 10. CommonCrawl URL index (recent month)
    try:
        idx_r = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=8,
                             headers={"User-Agent": "VulnusLab/1.0"})
        if idx_r.status_code == 200 and idx_r.json():
            recent_idx = idx_r.json()[0].get("cdx-api")
            if recent_idx:
                cc_r = requests.get(f"{recent_idx}?url=*.{host}/*&output=json&limit=200",
                                    timeout=15, headers={"User-Agent": "VulnusLab/1.0"})
                if cc_r.status_code == 200:
                    import json as _json
                    hosts = set()
                    for line in cc_r.text.splitlines()[:200]:
                        try:
                            row = _json.loads(line)
                            from urllib.parse import urlparse as _up
                            u = _up(row.get("url", ""))
                            if u.hostname and u.hostname.lower().endswith(host):
                                hosts.add(u.hostname.lower())
                        except Exception:
                            continue
                    _add_subs(hosts, "commoncrawl")
    except Exception as e:
        sources_failed["commoncrawl"] = str(e)[:80]

    # 11. DNS brute force — parallel resolution of common subdomain prefixes
    try:
        results = await asyncio.gather(*[_resolve_brute(host, p) for p in _BRUTE_WORDLIST])
        brute_found = [r for r in results if r]
        for name in brute_found:
            all_subs.add(name)
        sources_hit["dns_brute"] = len(brute_found)
    except Exception as e:
        sources_failed["dns_brute"] = str(e)[:80]

    return {
        "ok": True,
        # AMASS-SELF-FILTER-V1 — the apex host is not its own subdomain
        "subdomains": sorted(x for x in all_subs if x != host),
        "total_subdomains": len([x for x in all_subs if x != host]),
        "sources": sources_hit,
        "sources_failed": sources_failed,
        "engine": "pure-Python (6 passive sources + DNS brute, parallel)",
    }


# ── VL-FORGE wrapper around the existing implementation ────────────────
from tools._framework import ScanContext, run_scanner
from tools._payloads.amass_findings import AMASS_FINDING_RULES


@router.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather(ctx: ScanContext):
        # Call existing implementation; populate state from result
        result = await _recon_amass_impl(req)
        ctx.state["subdomains"] = result.get("subdomains") or []
        ctx.state["total_subdomains"] = result.get("total_subdomains") or 0
        ctx.state["sources"] = result.get("sources") or {}
        ctx.state["sources_failed"] = result.get("sources_failed") or {}
        # Source tracking for VL-FORGE
        for src, count in (ctx.state["sources"] or {}).items():
            if count > 0:
                ctx.source(f"{src} ({count})")
        # Display helpers
        if ctx.state["subdomains"]:
            ctx.state["sample_subs_display"] = ", ".join(ctx.state["subdomains"][:8])
        sources = ctx.state["sources"] or {}
        if sources:
            ctx.state["sources_breakdown_display"] = ", ".join(
                f"{k}({v})" for k, v in sources.items() if v > 0)
        failed = ctx.state["sources_failed"] or {}
        if failed:
            ctx.state["failed_sources_display"] = ", ".join(failed.keys())

    INTEL_FIELDS = [
        ("Total subdomains",     "total_subdomains"),
        ("Sample subdomains",   "sample_subs_display"),
        ("Sources breakdown",   "sources_breakdown_display"),
        ("Failed sources",       "failed_sources_display"),
    ]

    return await run_scanner(
        host=host, tool="amass",
        gather_func=gather,
        finding_rules=AMASS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains", "total_subdomains", "sources"],
    )


def register(app):
    app.include_router(router)
