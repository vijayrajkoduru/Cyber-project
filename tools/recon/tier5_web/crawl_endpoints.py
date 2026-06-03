"""crawl_endpoints — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import urllib.parse

router = APIRouter()

# Curated seed paths to bootstrap the crawler when the landing page has
# few internal links (SPAs, marketing pages). These are common entry points
# (admin/api/docs surfaces) — fetched in addition to discovered hrefs.
_SEED_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/docs", "/openapi.json",
    "/swagger.json", "/robots.txt", "/sitemap.xml", "/admin", "/login",
    "/health", "/status", "/version", "/.well-known/security.txt",
]


async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    domain = urllib.parse.urlparse(base).netloc
    visited = set()
    endpoints = []
    # Seed concurrent fetches with curated baseline paths.
    seed_urls = [urllib.parse.urljoin(base, p) for p in _SEED_PATHS]
    async def _fetch_one(u):
        c, _, b = await fetch(u, timeout=6)
        return (u, c, b)
    seed_results = await asyncio.gather(*(_fetch_one(u) for u in seed_urls))
    discovered = []
    for u, c, body in seed_results:
        visited.add(u)
        if c == 200 and body:
            endpoints.append(u)
            text = body.decode("utf-8", "ignore")
            for m in re.finditer(r'href=[\"\']([^\"\'#]+)', text):
                full = urllib.parse.urljoin(u, m.group(1))
                if (urllib.parse.urlparse(full).netloc == domain
                        and full not in visited
                        and full not in discovered):
                    discovered.append(full)
    # Second wave: crawl up to 15 newly-discovered same-origin links.
    second = discovered[:15]
    results = await asyncio.gather(*(_fetch_one(u) for u in second))
    for u, c, _ in results:
        if c == 200:
            endpoints.append(u)
    ctx.state["endpoints"] = endpoints[:50]
    ctx.state["count"] = len(endpoints)
    ctx.source("Curated-seed crawler (2-wave concurrent BFS)")

RULES = [

]

@router.post("/api/recon/crawl_endpoints")
async def recon_crawl_endpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="crawl_endpoints",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Endpoints","endpoints"),("Count","count")])

def register(app):
    app.include_router(router)
