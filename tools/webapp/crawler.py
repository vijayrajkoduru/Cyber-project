"""Webapp BFS crawler — seeded with AI-curated high-value paths.

Route: POST /api/webapp/crawler
Loads tools/_payloads/crawler_seed_paths.py (201 seeds: API/auth/admin/
account/upload/sitemap/health/CMS/SPA/e-commerce paths). Uses these as
priority starting points BEFORE following links, so we cover the
likely-sensitive surface even on sites with weak link graphs.

Workflow:
  1. Fetch homepage + extract same-origin links
  2. Combine with priority-ordered AI seed paths
  3. BFS-fetch each (capped at MAX_URLS), recording reachable URLs
  4. Emit a single info finding summarizing the crawl footprint
"""
import asyncio
import re
from urllib.parse import urlparse, urljoin

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()

_FALLBACK_SEEDS = [
    {"path": "/",         "category": "root",   "priority": 10},
    {"path": "/api",      "category": "api",    "priority": 10},
    {"path": "/login",    "category": "auth",   "priority": 9},
    {"path": "/admin",    "category": "admin",  "priority": 9},
    {"path": "/robots.txt","category": "sitemap","priority": 8},
    {"path": "/sitemap.xml","category": "sitemap","priority": 8},
]
try:
    from tools._payloads.crawler_seed_paths import CRAWLER_SEED_PATHS as _AI_SEEDS
    _SEEDS = list(_AI_SEEDS) if isinstance(_AI_SEEDS, list) and _AI_SEEDS else _FALLBACK_SEEDS
except Exception:
    _SEEDS = _FALLBACK_SEEDS

_MAX_URLS = 150          # hard cap on URLs visited per scan
_MAX_PER_HOST_DEPTH = 2  # BFS depth
_CONCURRENCY = 15
_TIMEOUT = httpx.Timeout(connect=3.0, read=4.0, write=3.0, pool=5.0)


async def _fetch(client, url, sem):
    async with sem:
        try:
            r = await client.get(url)
            return url, r.status_code, (r.text or "")[:200_000], dict(r.headers)
        except Exception:
            return url, None, "", {}


def _extract_same_origin_links(html, base_origin):
    """Return same-origin URLs found in href= and src=. Limited to ≤30/page."""
    out = []
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\'#?]+)', html or "", re.I):
        link = m.group(1).strip()
        if not link or link.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        joined = urljoin(base_origin + "/", link)
        parsed = urlparse(joined)
        if parsed.netloc and not parsed.netloc.endswith(urlparse(base_origin).netloc):
            continue
        out.append(joined)
        if len(out) >= 30: break
    return out


@router.post("/api/webapp/crawler")
@vl_verify(check_spa=True)
async def webapp_crawler(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    parsed = urlparse(base)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    visited = set()
    queue = []
    sem = asyncio.Semaphore(_CONCURRENCY)
    external_domains = set()
    crawl_log = []

    # Seed with priority-ordered AI paths
    for s in sorted(_SEEDS, key=lambda e: -int(e.get("priority", 5))):
        path = s.get("path", "")
        if not path: continue
        url = base_origin + (path if path.startswith("/") else "/" + path)
        if url not in visited:
            queue.append((url, 0))
            visited.add(url)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        depth_idx = 0
        while queue and len(visited) < _MAX_URLS and depth_idx < _MAX_PER_HOST_DEPTH + 1:
            batch = queue[:_MAX_URLS - len(crawl_log)]
            queue = queue[len(batch):]
            results = await asyncio.gather(
                *[_fetch(client, u, sem) for u, _ in batch],
                return_exceptions=True
            )
            for r in results:
                if isinstance(r, Exception) or r is None:
                    continue
                url, status, body, headers = r
                if status is None:
                    continue
                crawl_log.append({"url": url, "status": status, "size": len(body)})
                # Follow same-origin links from this body (only at depth < max)
                if depth_idx < _MAX_PER_HOST_DEPTH:
                    for link in _extract_same_origin_links(body, base_origin):
                        if link not in visited and len(visited) < _MAX_URLS:
                            visited.add(link)
                            queue.append((link, depth_idx + 1))
                        elif link not in visited:
                            p = urlparse(link)
                            if p.netloc != parsed.netloc:
                                external_domains.add(p.netloc)
            depth_idx += 1

    findings = []
    # Always emit one INFO finding summarizing the crawl
    findings.append(wrap_finding(
        f"{len(crawl_log)} URL(s) reachable across crawl",
        "POSITIVE",
        evidence_marker=(f"Seeded with {len(_SEEDS)} AI-curated paths; BFS depth {_MAX_PER_HOST_DEPTH}; "
                         f"{len(external_domains)} external domains linked"),
    ))
    # Flag interesting status codes
    s401 = [c for c in crawl_log if c["status"] == 401]
    s403 = [c for c in crawl_log if c["status"] == 403]
    if s401 or s403:
        findings.append(wrap_finding(
            f"Auth-walled endpoints discovered ({len(s401)} 401, {len(s403)} 403)",
            "INFO",
            evidence_marker=f"Sample: {', '.join(c['url'] for c in (s401 + s403)[:5])}",
        ))

    return standard_response(
        tool="crawler", target=req.target,
        findings=findings,
        tests_performed=len(crawl_log),
        tests_summary=f"Crawled {len(crawl_log)} URLs starting from {len(_SEEDS)} AI-curated seeds",
        raw_data={"crawler": {
            "urls_crawled": len(crawl_log),
            "external_domains": sorted(external_domains)[:15],
            "wordlist_source": f"AI-curated ({len(_SEEDS)} seeds)",
            "sample_urls": [c["url"] for c in crawl_log[:25]],
            "auth_walled_sample": [c["url"] for c in (s401 + s403)[:10]],
        }},
    )


def register(app):
    app.include_router(router)
