"""recon_crawl -- isolated tool (Kali-style architecture).

Route: /api/recon/crawl
Now handles:
  • Host-mismatch labs (Apache vhost / Tomcat connector returning 400 on
    Host: container-hostname) — falls back to Host: localhost.
  • Localhost redirects rewritten back to original target.
  • Relative href URLs without leading / (previously dropped).
"""

import asyncio
import re
from urllib.parse import urljoin
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, web_url,
)
import aiohttp as _aiohttp_crawl

router = APIRouter()

_INTERESTING_CRAWL = ["admin","login","config","backup","test","internal",
                       ".env",".git","api","swagger","console","dashboard","setup"]


@router.post("/api/recon/crawl")
async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    host = recon_host(req.target).lower()
    target_host_with_port = recon_host(req.target)
    MAX_DEPTH = 3
    MAX_PAGES = 80

    # Pre-flight: detect Host-mismatch (lab Apache rejects Host=container-name).
    extra_headers = {}
    try:
        async with _aiohttp_crawl.ClientSession() as _probe:
            async with _probe.get(base,
                                  timeout=_aiohttp_crawl.ClientTimeout(total=6),
                                  allow_redirects=False) as _r:
                if _r.status == 400:
                    extra_headers = {"Host": "localhost"}
    except Exception:
        pass

    visited = set()
    queue = [(base, 0)]
    pages = []
    interesting = set()

    async def _fetch(session, url):
        try:
            h = {"User-Agent": "Mozilla/5.0 VulnusLab", **extra_headers}
            # aiohttp auto-generates Host from URL — if we set a custom Host
            # we MUST also pass skip_auto_headers, otherwise aiohttp raises
            # ValueError("Header value is invalid") and the fetch silently
            # returns None.
            kwargs = dict(timeout=_aiohttp_crawl.ClientTimeout(total=6),
                          allow_redirects=True, headers=h)
            if "Host" in extra_headers:
                kwargs["skip_auto_headers"] = ["Host"]
            async with session.get(url, **kwargs) as r:
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
                    for m in re.findall(r'href=["\'](.*?)["\']', body):
                        try:
                            if m.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                                continue
                            # Rewrite localhost-redirects back to target host.
                            if "://localhost" in m:
                                m = m.replace("://localhost", f"://{target_host_with_port}")
                            if m.startswith("http"):
                                if recon_host(m).lower() == host:
                                    queue.append((m, depth + 1))
                            elif m.startswith("/"):
                                queue.append((base + m, depth + 1))
                            else:
                                # Relative URL without leading / (e.g. "index.php")
                                queue.append((urljoin(url + "/", m), depth + 1))
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
        "engine": f"pure-Python BFS crawler (depth {MAX_DEPTH}, Host fallback, relative-URL support)",
    }


def register(app):
    app.include_router(router)
