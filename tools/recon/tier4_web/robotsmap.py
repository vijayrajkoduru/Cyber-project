"""robots + sitemap v2 — VL-FORGE pattern.

Route: /api/recon/robotsmap

Sources (parallel):
  1. robots.txt fetch + Disallow extraction
  2. sitemap.xml fetch + recursive sitemap-index following
  3. /.well-known/security.txt probe
  4. Other /.well-known/ endpoints probe (RFC 9116)
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.robotsmap_findings import (
    ROBOTSMAP_FINDING_RULES, classify_disallow,
)

router = APIRouter()


_WELL_KNOWN_PROBES = [
    "security.txt",
    "openid-configuration",
    "oauth-authorization-server",
    "change-password",
    "host-meta",
    "webfinger",
    "assetlinks.json",
    "apple-app-site-association",
]


def _fetch(url):
    try:
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            return r.text or ""
        return None
    except Exception:
        return None


def _parse_robots(text):
    """Extract Disallow + Allow + Sitemap lines."""
    disallowed = []
    allowed = []
    sitemaps = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path: disallowed.append(path)
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path: allowed.append(path)
        elif line.lower().startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url: sitemaps.append(url)
    return disallowed, allowed, sitemaps


def _parse_sitemap_xml(text, max_urls=500):
    """Extract <loc> URLs from sitemap XML. Handles both urlset and sitemapindex."""
    urls = []
    sub_sitemaps = []
    for m in re.finditer(r"<loc>([^<]+)</loc>", text):
        url = m.group(1).strip()
        if url.endswith(".xml") or "sitemap" in url.lower():
            sub_sitemaps.append(url)
        else:
            urls.append(url)
        if len(urls) >= max_urls: break
    return urls, sub_sitemaps


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")

    robots_url = base + "/robots.txt"
    sitemap_url = base + "/sitemap.xml"
    well_known_base = base + "/.well-known/"

    # Fire all in parallel
    robots_task = asyncio.to_thread(_fetch, robots_url)
    sitemap_task = asyncio.to_thread(_fetch, sitemap_url)
    wellknown_tasks = [asyncio.to_thread(_fetch, well_known_base + p)
                       for p in _WELL_KNOWN_PROBES]

    robots_text, sitemap_text, *wk_results = await asyncio.gather(
        robots_task, sitemap_task, *wellknown_tasks,
    )

    ctx.state["base_reachable"] = robots_text is not None or sitemap_text is not None

    # robots.txt parsing
    if robots_text:
        ctx.source("robots.txt-fetch")
        ctx.state["robots_txt"] = robots_text[:5000]
        disallowed, allowed, robot_sitemaps = _parse_robots(robots_text)
        ctx.state["disallowed"] = disallowed
        ctx.state["allowed"] = allowed
        ctx.state["robot_sitemaps"] = robot_sitemaps

        # Classify sensitive Disallow entries
        sensitive_disallow = []
        for path in disallowed:
            why = classify_disallow(path)
            if why:
                sensitive_disallow.append({"path": path, "why": why})
        ctx.state["sensitive_disallow"] = sensitive_disallow

    # sitemap.xml parsing
    all_sitemap_urls = []
    if sitemap_text:
        ctx.source("sitemap.xml-fetch")
        urls, subs = _parse_sitemap_xml(sitemap_text)
        all_sitemap_urls.extend(urls)

        # Fetch sub-sitemaps (cap 5)
        if subs:
            sub_responses = await asyncio.gather(*[
                asyncio.to_thread(_fetch, su) for su in subs[:5]
            ])
            for sub_text in sub_responses:
                if sub_text:
                    sub_urls, _ = _parse_sitemap_xml(sub_text, max_urls=200)
                    all_sitemap_urls.extend(sub_urls)
            if any(sub_responses):
                ctx.source("sub-sitemap-fetch")

    ctx.state["sitemap_urls"] = all_sitemap_urls[:500]

    # /.well-known/ endpoints
    well_known_found = []
    for probe, resp in zip(_WELL_KNOWN_PROBES, wk_results):
        if resp:
            well_known_found.append(probe)
            if probe == "security.txt":
                ctx.state["security_txt"] = resp[:2000]
    ctx.state["well_known_found"] = well_known_found
    if well_known_found:
        ctx.source(f"well-known-probe-{len(well_known_found)}")

    # Backwards-compat
    ctx.state["disallow"] = ctx.state.get("disallowed") or []
    ctx.state["sitemap"] = ctx.state.get("sitemap_urls") or []
    ctx.state["well_known"] = well_known_found
    ctx.state["total"] = (len(ctx.state.get("disallowed") or []) +
                           len(ctx.state.get("sitemap_urls") or []) +
                           len(well_known_found))


INTEL_FIELDS = [
    ("robots.txt rules",         "robots_summary_display"),
    ("Sitemap URL count",        "sitemap_count_display"),
    ("Sensitive disallows",      "sensitive_disallow_display"),
    ("security.txt",             "security_txt_status_display"),
    ("/.well-known/ endpoints",  "well_known_display"),
]


@router.post("/api/recon/robotsmap")
async def recon_robotsmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        d = ctx.state.get("disallowed") or []
        a = ctx.state.get("allowed") or []
        if d or a:
            ctx.state["robots_summary_display"] = (
                f"{len(d)} Disallow + {len(a)} Allow rules")
        sm = ctx.state.get("sitemap_urls") or []
        if sm:
            ctx.state["sitemap_count_display"] = f"{len(sm)} URLs"
        sd = ctx.state.get("sensitive_disallow") or []
        if sd:
            ctx.state["sensitive_disallow_display"] = (
                f"{len(sd)} sensitive: " +
                ", ".join(x["path"] for x in sd[:3]))
        ctx.state["security_txt_status_display"] = (
            "Present" if ctx.state.get("security_txt") else "Missing")
        wk = ctx.state.get("well_known_found") or []
        if wk:
            ctx.state["well_known_display"] = ", ".join(wk[:5])

    return await run_scanner(
        host=host, tool="robotsmap",
        gather_func=gather_with_display,
        finding_rules=ROBOTSMAP_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["disallow", "sitemap", "well_known", "total"],
    )


def register(app):
    app.include_router(router)
