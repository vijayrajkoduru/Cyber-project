"""recon_crawl -- isolated tool (Kali-style architecture).

Route: /api/recon/crawl
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

_INTERESTING_CRAWL = ["admin","login","config","backup","test","internal",
                       ".env",".git","api","swagger","console","dashboard","setup"]

@router.post("/api/recon/crawl")
async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    host = recon_host(req.target).lower()
    MAX_DEPTH = 3
    MAX_PAGES = 80

    visited = set()
    queue = [(base, 0)]
    pages = []
    interesting = set()

    async def _fetch(session, url):
        try:
            async with session.get(url,
                                   timeout=_aiohttp_crawl.ClientTimeout(total=6),
                                   allow_redirects=True,
                                   headers={"User-Agent": "Mozilla/5.0 VulnusLab"}) as r:
                text = await r.text()
                return r.status, text
        except Exception:
            return None, None

    async with _aiohttp_crawl.ClientSession() as session:
        while queue and len(pages) < MAX_PAGES:
            batch = []
            while queue and len(batch) < 15:
                u, d = queue.pop(0)
                if u in visited or d > MAX_DEPTH:
                    continue
                visited.add(u)
                batch.append((u, d))
            if not batch:
                continue
            results = await asyncio.gather(*[_fetch(session, u) for u, _ in batch])
            for (url, depth), (status, body) in zip(batch, results):
                if status is None:
                    continue
                pages.append({"url": url, "depth": depth, "status": status})
                for kw in _INTERESTING_CRAWL:
                    if kw in url.lower():
                        interesting.add(url)
                        break
                if depth < MAX_DEPTH and body:
                    for m in re.findall(r'href=["\']([^"\']+)["\']', body):
                        try:
                            if m.startswith("http"):
                                if recon_host(m).lower() == host:
                                    queue.append((m, depth + 1))
                            elif m.startswith("/"):
                                queue.append((base + m, depth + 1))
                        except Exception:
                            continue

    return {
        "ok": True,
        "urls": [p["url"] for p in pages],
        "details": pages,
        "interesting": sorted(interesting)[:30],
        "total": len(pages),
        "interesting_total": len(interesting),
        "depth_reached": max((p["depth"] for p in pages), default=0),
        "engine": f"pure-Python BFS crawler (depth {MAX_DEPTH}, parallel async, same-origin)",
    }


def register(app):
    app.include_router(router)
