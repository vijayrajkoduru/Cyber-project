"""recon_wayback -- isolated tool (Kali-style architecture).

Route: /api/recon/wayback
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

# Substrings that mark an archived URL as "interesting" — admin panels,
# leaked creds, backup files, source-control metadata. The frontend table
# highlights these because they're the actionable leads for a pentester.
_INTERESTING_HINTS = (
    "admin", "login", "signin", "register", "/api/", "/v1/", "/v2/",
    "/graphql", "swagger", "openapi", ".env", ".git", ".svn", "config",
    "backup", "dump", "db.sql", "phpinfo", "debug", "wp-config",
    "/.well-known/", "credentials", "token", "secret", "key=", "api_key",
    ".bak", ".old", ".zip", ".tar", ".log", "actuator",
)


async def recon_wayback_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Archived URL discovery from 3 sources: Wayback Machine, CommonCrawl, URLScan.io."""
    host = recon_host(req.target)
    all_urls = set()
    sources_hit = {}
    sources_failed = {}

    # Source 1 — Wayback Machine CDX
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit=300&filter=statuscode:200",
            timeout=15, headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code == 200:
            rows = r.json()
            urls = [row[2] for row in rows[1:]] if rows and len(rows) > 1 else []
            before = len(all_urls)
            for u in urls:
                all_urls.add(u)
            sources_hit["wayback"] = len(all_urls) - before
        else:
            sources_failed["wayback"] = f"status {r.status_code}"
    except Exception as e:
        sources_failed["wayback"] = str(e)[:80]

    # Source 2 — CommonCrawl most-recent index
    try:
        idx_r = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=8,
                             headers={"User-Agent": "VulnusLab/1.0"})
        if idx_r.status_code == 200 and idx_r.json():
            recent_idx = idx_r.json()[0].get("cdx-api")
            if recent_idx:
                cc_r = requests.get(f"{recent_idx}?url=*.{host}/*&output=json&limit=300",
                                    timeout=15, headers={"User-Agent": "VulnusLab/1.0"})
                if cc_r.status_code == 200:
                    import json as _json
                    before = len(all_urls)
                    for line in cc_r.text.splitlines()[:300]:
                        try:
                            row = _json.loads(line)
                            u = row.get("url", "")
                            if u:
                                all_urls.add(u)
                        except Exception:
                            continue
                    sources_hit["commoncrawl"] = len(all_urls) - before
    except Exception as e:
        sources_failed["commoncrawl"] = str(e)[:80]

    # Source 3 — URLScan.io
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100",
                         timeout=10, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            data = r.json()
            before = len(all_urls)
            for item in data.get("results", []):
                u = item.get("page", {}).get("url", "")
                if u:
                    all_urls.add(u)
            sources_hit["urlscan_io"] = len(all_urls) - before
    except Exception as e:
        sources_failed["urlscan_io"] = str(e)[:80]

    # Rank interesting URLs first — keeps the most useful entries inside
    # the 500-row cap when archive.org returns tens of thousands of hits.
    sorted_urls = sorted(all_urls)
    interesting = [u for u in sorted_urls
                   if any(h in u.lower() for h in _INTERESTING_HINTS)]
    return {
        "ok":                True,
        "urls":              sorted_urls[:500],
        "discovered":        sorted_urls[:500],
        "interesting":       interesting[:200],
        "interesting_total": len(interesting),
        "total":             len(all_urls),
        "sources":           sources_hit,
        "sources_failed":    sources_failed,
        "engine":            "pure-Python (Wayback + CommonCrawl + URLScan.io)",
    }


# VLERR-WRAP-V1
@router.post("/api/recon/wayback")
async def recon_wayback(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_wayback_impl(req, _)
    except Exception as _e:
        return {"ok": False, "urls": [], "discovered": [],
                "interesting": [], "interesting_total": 0, "total": 0,
                "sources": {}, "sources_failed": {},
                "skipped_reason": f"wayback scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                "error": str(_e)[:300]}


def register(app):
    app.include_router(router)
