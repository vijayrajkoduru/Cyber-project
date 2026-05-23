"""Dork Harvest v1 — VL-FORGE pattern.

Route: /api/recon/dork_harvest

Runs targeted search-engine dorks against the target domain — finds content
that Google/Bing have indexed but shouldn't be public (configs, dumps, logs,
admin panels). Uses DuckDuckGo HTML scraping to avoid API key requirements.

Sources (parallel):
  1. site:<host> filetype:env / .sql / .log / .bak / .zip — exposed file types
  2. site:<host> inurl:admin / inurl:login / inurl:config — admin panels
  3. site:<host> intext:"index of" — directory listings
"""
import asyncio
import re
import urllib.parse

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import DORK_HARVEST_FINDING_RULES

router = APIRouter()


# Each dork: (label, search query, severity-hint)
_DORKS = [
    # Critical — exposed configs / dumps
    ("Env files",       'filetype:env',            "critical"),
    ("SQL dumps",       'filetype:sql',            "critical"),
    ("Backup files",    'filetype:bak OR filetype:backup', "critical"),
    ("ZIP archives",    'filetype:zip',            "critical"),
    ("Log files",       'filetype:log',            "high"),
    # Admin panels / sensitive paths
    ("Admin URLs",      'inurl:admin',             "medium"),
    ("Login URLs",      'inurl:login',             "info"),
    ("Config URLs",     'inurl:config',            "high"),
    ("Database URLs",   'inurl:db OR inurl:database', "high"),
    # Directory listings
    ("Directory list",  'intitle:"index of"',      "critical"),
    # Sensitive doctypes
    ("Excel sheets",    'filetype:xlsx OR filetype:xls', "medium"),
    ("Word docs",       'filetype:docx OR filetype:doc', "medium"),
]


def _ddg_search(query):
    """DuckDuckGo HTML — no API key, gets ~30 results per query.
    Returns list of {title, url, snippet}.
    """
    try:
        r = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            timeout=8,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnusLab/1.0"})
        if r.status_code != 200: return []
        results = []
        # Extract result blocks: <a class="result__a" href="...">title</a>
        for m in re.finditer(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            r.text):
            url = m.group(1)
            title = re.sub(r"<[^>]+>", "", m.group(2))[:140]
            # DDG wraps URLs in their redirect — unwrap
            redirect = re.search(r"uddg=([^&]+)", url)
            if redirect:
                try: url = urllib.parse.unquote(redirect.group(1))
                except Exception: pass
            results.append({"title": title.strip(), "url": url[:240]})
            if len(results) >= 15: break
        return results
    except Exception:
        return []


def _run_dork(host, label, query, severity):
    """Run a single dork: prepend site:<host> + run the search."""
    full_q = f"site:{host} {query}"
    hits = _ddg_search(full_q)
    if not hits: return None
    return {
        "dork":     label,
        "query":    full_q,
        "severity": severity,
        "hits":     hits,
        "count":    len(hits),
    }


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["engines_used"] = ["DuckDuckGo HTML"]
    ctx.state["dorks_run"]    = len(_DORKS)

    # Run all dorks in parallel
    results = await asyncio.gather(*[
        asyncio.to_thread(_run_dork, host, label, query, sev)
        for label, query, sev in _DORKS
    ])
    active = [r for r in results if r]
    ctx.state["dork_results"] = active

    # Aggregate into severity buckets
    critical_hits = []
    indexed_files = []
    categories    = {}
    for r in active:
        for h in r.get("hits") or []:
            entry = {"dork": r["dork"], "url": h.get("url", ""), "title": h.get("title", "")}
            if r["severity"] == "critical":
                critical_hits.append(entry)
            indexed_files.append(entry)
            categories[r["dork"]] = categories.get(r["dork"], 0) + 1

    ctx.state["critical_hits"]   = critical_hits[:30]
    ctx.state["indexed_files"]   = indexed_files[:60]
    ctx.state["file_categories"] = categories

    ctx.source(f"duckduckgo-html ({len(_DORKS)} dorks)")
    if active:
        ctx.source(f"dork-hits ({sum(r['count'] for r in active)} URLs)")


INTEL_FIELDS = [
    ("Dorks executed",      "dorks_run"),
    ("Critical exposures",  "critical_display"),
    ("Total indexed URLs",  "total_display"),
    ("Top categories",      "categories_display"),
    ("Sample hits",         "sample_display"),
]


@router.post("/api/recon/dork_harvest")
async def recon_dork_harvest(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ch = ctx.state.get("critical_hits") or []
        if ch: ctx.state["critical_display"] = f"{len(ch)} sensitive file(s) indexed by search engines"
        idx = ctx.state.get("indexed_files") or []
        if idx: ctx.state["total_display"] = f"{len(idx)} indexed URL(s) across {len(ctx.state.get('file_categories',{}))} categories"
        cats = ctx.state.get("file_categories") or {}
        if cats:
            top = sorted(cats.items(), key=lambda kv: -kv[1])[:5]
            ctx.state["categories_display"] = ", ".join(f"{k}: {v}" for k, v in top)
        if ch:
            ctx.state["sample_display"] = "; ".join(
                f"{x.get('dork','?')}: {x.get('url','?')[:60]}" for x in ch[:3])

    return await run_scanner(
        host=host, tool="dork_harvest",
        gather_func=gather_with_display,
        finding_rules=DORK_HARVEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["critical_hits", "indexed_files", "dorks_run"],
    )


def register(app):
    app.include_router(router)
