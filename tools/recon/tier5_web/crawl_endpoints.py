"""crawl_endpoints — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import urllib.parse

router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    visited = set(); queue = [base]; endpoints = []
    domain = urllib.parse.urlparse(base).netloc
    while queue and len(visited) < 30:
        u = queue.pop(0)
        if u in visited: continue
        visited.add(u)
        code, _, body = await fetch(u, timeout=6)
        if code != 200 or not body: continue
        endpoints.append(u)
        text = body.decode("utf-8","ignore")
        for m in re.finditer(r'href=[\"\']([^\"\'#]+)', text):
            link = m.group(1)
            full = urllib.parse.urljoin(u, link)
            if urllib.parse.urlparse(full).netloc == domain and full not in visited and len(queue) < 50:
                queue.append(full)
    ctx.state["endpoints"] = endpoints[:50]
    ctx.state["count"] = len(endpoints)
    ctx.source("BFS same-origin crawler (cap 30 URLs)")

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
