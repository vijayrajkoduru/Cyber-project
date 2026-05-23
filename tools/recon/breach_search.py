"""Breach Search v1 — VL-FORGE pattern.

Route: /api/recon/breach_search

Checks if the target domain appears in known data breaches + paste-site dumps.
Pure-Python; uses HaveIBeenPwned breaches API (unauthenticated, free domain
search) + IntelligenceX-style paste index.

Sources (parallel):
  1. HIBP breaches API — all breaches matching domain
  2. Paste-site keyword index — pastebin/ghostbin/dpaste mentions
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import BREACH_SEARCH_FINDING_RULES

router = APIRouter()


def _fetch_hibp_breaches(host):
    """HIBP breaches API — unauthenticated, returns all breaches indexed by domain.
    Endpoint: https://haveibeenpwned.com/api/v3/breaches?domain=<host>
    """
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": host},
            timeout=8,
            headers={"User-Agent": "VulnusLab/1.0", "hibp-api-version": "3"})
        if r.status_code == 200:
            return [{
                "name":      b.get("Name", "?"),
                "title":     b.get("Title", "?"),
                "date":      b.get("BreachDate", "?"),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                "verified":  b.get("IsVerified", False),
            } for b in r.json()]
        return []
    except Exception:
        return []


def _fetch_paste_index(host):
    """Search Google for paste-site mentions of the domain.
    Pure-Python — no API key needed, uses search-engine result scraping.
    """
    pastes = []
    paste_sites = ["pastebin.com", "ghostbin.co", "dpaste.com", "rentry.co",
                   "controlc.com", "paste.ee", "0bin.net"]
    for site in paste_sites:
        try:
            r = requests.get(
                "https://html.duckduckgo.com/html/",
                params={"q": f"site:{site} {host}"},
                timeout=6,
                headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"})
            if r.status_code != 200:
                continue
            # Extract result URLs
            for m in re.finditer(r'href="(https?://[^"]*' + re.escape(site) + r'/[^"]+)"', r.text):
                url = m.group(1)
                if site in url and url not in [p["url"] for p in pastes]:
                    pastes.append({"source": site, "url": url[:200],
                                    "title": f"Paste containing '{host}'"})
                    if len(pastes) >= 20: break
            if len(pastes) >= 20: break
        except Exception:
            continue
    return pastes


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["api_reachable"] = True

    breaches_task = asyncio.to_thread(_fetch_hibp_breaches, host)
    pastes_task   = asyncio.to_thread(_fetch_paste_index, host)
    breaches, pastes = await asyncio.gather(breaches_task, pastes_task)

    ctx.state["breaches"] = breaches
    ctx.state["pastes"]   = pastes
    ctx.state["breach_count"] = len(breaches)
    ctx.state["paste_count"]  = len(pastes)
    ctx.source("hibp-breaches-api")
    if pastes: ctx.source(f"paste-site-index ({len(pastes)})")

    # Aggregate exposure
    total_accounts = sum(b.get("pwn_count", 0) for b in breaches)
    ctx.state["total_accounts_exposed"] = total_accounts


INTEL_FIELDS = [
    ("Breaches found",       "breach_count_display"),
    ("Accounts exposed",    "accounts_display"),
    ("Paste-site hits",      "paste_count_display"),
    ("Top breaches",         "top_breaches_display"),
]


@router.post("/api/recon/breach_search")
async def recon_breach_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        n = ctx.state.get("breach_count", 0)
        if n: ctx.state["breach_count_display"] = f"{n} breach(es) match this domain"
        acc = ctx.state.get("total_accounts_exposed", 0)
        if acc: ctx.state["accounts_display"] = f"{acc:,} account(s) compromised across all breaches"
        p = ctx.state.get("paste_count", 0)
        if p: ctx.state["paste_count_display"] = f"{p} paste mention(s)"
        b = ctx.state.get("breaches") or []
        if b:
            top = sorted(b, key=lambda x: -x.get("pwn_count", 0))[:3]
            ctx.state["top_breaches_display"] = "; ".join(
                f"{t.get('title','?')} ({t.get('date','?')}, {t.get('pwn_count',0):,} accts)"
                for t in top)

    return await run_scanner(
        host=host, tool="breach_search",
        gather_func=gather_with_display,
        finding_rules=BREACH_SEARCH_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["breaches", "pastes", "breach_count", "paste_count"],
    )


def register(app):
    app.include_router(router)
