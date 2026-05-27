"""search_engine_scrape — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import urllib.request, urllib.parse, re

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    found = set()
    try:
        q = urllib.parse.quote(f"site:{h} -site:www.{h}")
        url = f"https://www.bing.com/search?q={q}&count=50"
        def _fetch():
            req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.read().decode("utf-8","ignore")
        body = await asyncio.to_thread(_fetch)
        for m in re.finditer(rf"https?://([a-z0-9-]+\.{re.escape(h)})", body):
            found.add(m.group(1).lower())
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    verified = await bulk_check(list(found), concurrency=15)
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source("Bing site: search + DNS verification")

RULES = [

]

@router.post("/api/recon/search_engine_scrape")
async def recon_search_engine_scrape(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="search_engine_scrape",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
