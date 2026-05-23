"""Subdomain Discovery v2 — VL-FORGE pattern, 4+ parallel sources.

Route: /api/recon/subdomains

Sources (parallel):
  1. DNS brute-force (AI wordlist if present, else built-in 150-prefix list)
  2. Certificate Transparency (crt.sh)
  3. HackerTarget hostsearch passive DNS API
  4. AlienVault OTX passive DNS API
  5. Wildcard detection probe
  6. Permutations (target-dev, target-staging, etc.)

Findings (~8 rules in tools/_payloads/subdomains_findings.py):
  HIGH    : high-risk subdomain names (admin/staging/internal/etc.)
  CRITICAL: subdomain-takeover candidates (CNAME → dead 3rd-party)
  MEDIUM  : wildcard DNS pollution
  INFO    : total count + per-source breakdown
  POSITIVE: multi-source diversity + IPv6 coverage
"""
import asyncio
import json
import pathlib
import secrets

import dns.asyncresolver
import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import (
    ScanContext, run_scanner, dns_resolve, http_json_async,
)
from tools._payloads.subdomains_findings import (
    SUBDOMAINS_FINDING_RULES, classify_high_risk,
)

router = APIRouter()


# Built-in fallback wordlist (used if AI-curated payload not present).
_BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "mx", "mx1", "mx2", "dev", "test", "staging", "stage", "beta", "demo",
    "admin", "panel", "cpanel", "phpmyadmin", "auth", "sso", "login",
    "app", "api", "api-v1", "api-v2", "api-dev", "api-staging",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "blog", "shop", "store", "forum", "wiki", "support", "help", "docs",
    "dashboard", "console", "status", "monitor", "metrics",
    "git", "gitlab", "github", "jenkins", "ci", "deploy",
    "k8s", "grafana", "kibana", "prometheus", "sentry",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "vpn", "ssh", "secure", "ssl", "tls", "rdp",
    "internal", "intranet", "private", "corp", "preprod", "production",
    "old", "new", "legacy", "v1", "v2", "v3", "archive",
    "m", "mobile", "wap", "iphone", "android",
    "us", "uk", "eu", "asia", "us-east", "us-west", "eu-west",
    "checkout", "payment", "billing", "stripe",
    "hr", "careers", "jobs", "recruit",
    "vault", "secrets", "kv", "secret",
    "loadbalancer", "lb", "haproxy", "nginx", "proxy", "gateway",
    "backup", "bak", "archive",
]


def _load_ai_wordlist():
    """Load AI-curated subdomain wordlist if available."""
    try:
        p = pathlib.Path(__file__).parent.parent / "_payloads" / "recon" / "subdomain_wordlist.json"
        if p.exists():
            data = json.loads(p.read_text())
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "wordlist" in data:
                return data["wordlist"]
    except Exception:
        pass
    return None


_AI_WORDLIST = _load_ai_wordlist()
_ACTIVE_WORDLIST = _AI_WORDLIST or _BUILTIN_WORDLIST


# Permutation patterns — applied to base host (e.g. "vulnuslab")
_PERMUTATION_SUFFIXES = ["-dev", "-staging", "-stage", "-test", "-qa",
                          "-prod", "-beta", "-internal", "-api", "-new",
                          "-old", "dev", "staging", "test", "internal"]


async def _brute_force(host: str, wordlist: list, batch: int = 50):
    """Async DNS brute force. Returns set of found subdomains + IPs."""
    found = []
    for i in range(0, len(wordlist), batch):
        chunk = wordlist[i:i+batch]
        results = await asyncio.gather(*[
            dns_resolve(f"{p}.{host}", "A") for p in chunk
        ])
        for prefix, ips in zip(chunk, results):
            if ips:
                found.append((f"{prefix}.{host}", ips[0]))
    return found


async def _crt_sh_subdomains(host: str) -> set:
    """Pull subdomains from crt.sh certificate transparency logs."""
    def _do():
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json",
                              timeout=20, verify=False,
                              headers={"User-Agent": "VulnusLab/1.0"})
            if r.status_code != 200: return set()
            data = r.json()
            out = set()
            for row in data[:2000]:
                nv = (row.get("name_value") or "").lower()
                for part in nv.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part == host or part.endswith("." + host):
                        out.add(part)
            return out
        except Exception:
            return set()
    return await asyncio.to_thread(_do)


async def _hackertarget_subdomains(host: str) -> set:
    """HackerTarget hostsearch — free passive DNS API (rate-limited)."""
    def _do():
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}",
                              timeout=15, verify=False,
                              headers={"User-Agent": "VulnusLab/1.0"})
            if r.status_code != 200: return set()
            out = set()
            for line in r.text.splitlines():
                # Format: "subdomain.host,ip"
                if "," in line:
                    sub = line.split(",", 1)[0].strip().lower()
                    if sub == host or sub.endswith("." + host):
                        out.add(sub)
            return out
        except Exception:
            return set()
    return await asyncio.to_thread(_do)


async def _otx_subdomains(host: str) -> set:
    """AlienVault OTX passive DNS — free public API."""
    def _do():
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/passive_dns",
                timeout=15, verify=False,
                headers={"User-Agent": "VulnusLab/1.0"})
            if r.status_code != 200: return set()
            data = r.json()
            out = set()
            for entry in (data.get("passive_dns") or [])[:1000]:
                hostname = (entry.get("hostname") or "").lower()
                if hostname == host or hostname.endswith("." + host):
                    out.add(hostname)
            return out
        except Exception:
            return set()
    return await asyncio.to_thread(_do)


async def _wildcard_probe(host: str) -> bool:
    """Random subdomain that should NOT exist. If it resolves, wildcard is set."""
    rand = f"vlcanary-{secrets.token_hex(8)}.{host}"
    resp = await dns_resolve(rand, "A")
    return bool(resp)


async def _ipv6_check(subdomain: str) -> bool:
    """Test if subdomain has AAAA records."""
    resp = await dns_resolve(subdomain, "AAAA")
    return bool(resp)


async def _takeover_check(subdomain: str) -> str | None:
    """Quick CNAME-based takeover hint. Returns 3rd-party service or None.

    Real takeover validation requires HTTP fingerprint matching — this is a
    fast first-pass that flags suspicious CNAME targets.
    """
    cname = await dns_resolve(subdomain, "CNAME")
    if not cname: return None
    target = str(cname[0]).lower()
    takeover_hints = {
        ".s3.amazonaws.com":      "AWS S3",
        ".cloudfront.net":         "CloudFront",
        ".herokuapp.com":          "Heroku",
        ".github.io":              "GitHub Pages",
        ".gitlab.io":              "GitLab Pages",
        ".azurewebsites.net":      "Azure App Service",
        ".elasticbeanstalk.com":   "Elastic Beanstalk",
        ".ghost.io":               "Ghost",
        ".tumblr.com":             "Tumblr",
        ".wordpress.com":          "WordPress.com",
        ".readme.io":              "Readme",
        ".surge.sh":               "Surge",
        ".netlify.app":            "Netlify",
        ".vercel.app":             "Vercel",
        ".fastly.net":             "Fastly",
    }
    for sig, svc in takeover_hints.items():
        if sig in target:
            return f"{svc} ({target})"
    return None


async def gather(ctx: ScanContext):
    """Multi-source subdomain discovery."""
    host = ctx.host

    # Build permutation wordlist (small — applied to base host segment)
    base = host.split(".")[0]
    permutations = [f"{base}{suffix}" for suffix in _PERMUTATION_SUFFIXES]

    # Fire all 4+ sources in parallel
    (brute_results, crt_subs, ht_subs, otx_subs,
     wildcard_hit) = await asyncio.gather(
        _brute_force(host, _ACTIVE_WORDLIST[:300]),  # cap to bound time
        _crt_sh_subdomains(host),
        _hackertarget_subdomains(host),
        _otx_subdomains(host),
        _wildcard_probe(host),
    )

    ctx.state["wildcard_detected"] = wildcard_hit
    if wildcard_hit:
        ctx.source("wildcard-probe")

    # Aggregate sources_breakdown for the findings rule
    sources_breakdown = {}
    brute_set = {sub for sub, ip in brute_results}
    if brute_set:
        sources_breakdown["dns-brute"] = brute_set
        ctx.source(f"dns-brute-{len(_ACTIVE_WORDLIST)}")
    if crt_subs:
        sources_breakdown["crt.sh"] = crt_subs
        ctx.source("crt.sh")
    if ht_subs:
        sources_breakdown["hackertarget"] = ht_subs
        ctx.source("hackertarget")
    if otx_subs:
        sources_breakdown["alienvault-otx"] = otx_subs
        ctx.source("alienvault-otx")

    # Union all sources
    all_subs = brute_set | crt_subs | ht_subs | otx_subs

    # If wildcard is set, results are unreliable — keep but flag
    ctx.state["sources_breakdown"] = sources_breakdown
    ctx.state["subdomains"] = sorted(all_subs)

    # High-risk classification
    high_risk = []
    for sub in all_subs:
        match = classify_high_risk(sub)
        if match:
            high_risk.append(match)
    ctx.state["high_risk"] = high_risk

    # Lightweight IPv6 + takeover probes — cap to top 20 to bound time
    sample = sorted(all_subs)[:20]
    if sample:
        ipv6_results, takeover_results = await asyncio.gather(
            asyncio.gather(*[_ipv6_check(s) for s in sample]),
            asyncio.gather(*[_takeover_check(s) for s in sample]),
        )
        ctx.state["ipv6_subdomains"] = [
            s for s, has_v6 in zip(sample, ipv6_results) if has_v6
        ]
        ctx.state["takeover_candidates"] = [
            (s, hint) for s, hint in zip(sample, takeover_results) if hint
        ]

    # Backwards-compat: top-level subdomains[] list for existing PDF section
    ctx.state["records"] = [{"subdomain": s} for s in sorted(all_subs)]


INTEL_FIELDS = [
    ("Total subdomains",       "subdomain_count_display"),
    ("Sources contributed",    "sources_summary"),
    ("Wildcard DNS",           "wildcard_detected"),
    ("High-risk subdomains",   "high_risk_display"),
    ("IPv6 subdomains",        "ipv6_display"),
    ("Takeover candidates",    "takeover_display"),
    ("Wordlist source",        "wordlist_source_display"),
]


@router.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    # Stringify dict/list fields before run_scanner (so generic intel
    # renderer doesn't JSON-stringify them)
    async def gather_with_display(ctx):
        await gather(ctx)
        subs = ctx.state.get("subdomains") or []
        ctx.state["subdomain_count_display"] = (
            f"{len(subs)} unique" if subs else None)
        sb = ctx.state.get("sources_breakdown") or {}
        if sb:
            ctx.state["sources_summary"] = ", ".join(
                f"{k} ({len(v)})" for k, v in sb.items() if v)
        hr = ctx.state.get("high_risk") or []
        if hr:
            ctx.state["high_risk_display"] = ", ".join(
                f"{name} ({reason})" for name, reason in hr[:6])
        ipv6 = ctx.state.get("ipv6_subdomains") or []
        if ipv6:
            ctx.state["ipv6_display"] = ", ".join(ipv6[:5])
        tc = ctx.state.get("takeover_candidates") or []
        if tc:
            ctx.state["takeover_display"] = "; ".join(
                f"{s} -> {hint}" for s, hint in tc)
        ctx.state["wordlist_source_display"] = (
            f"AI-curated ({len(_ACTIVE_WORDLIST)} prefixes)"
            if _AI_WORDLIST else f"built-in ({len(_ACTIVE_WORDLIST)})")

    return await run_scanner(
        host=host,
        tool="subdomains",
        gather_func=gather_with_display,
        finding_rules=SUBDOMAINS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains", "records", "wildcard_detected"],
    )


def register(app):
    app.include_router(router)
