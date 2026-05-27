"""wayback_subdomain_extract — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import urllib.request, urllib.parse, json, re

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    found = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{h}/*&output=json&fl=original&collapse=urlkey&limit=300"
        def _fetch():
            req = urllib.request.Request(url, headers={"User-Agent":"VulnusLab"})
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        data = await asyncio.to_thread(_fetch)
        for row in data[1:]:
            try:
                u = row[0]
                p = urllib.parse.urlparse(u)
                host = (p.hostname or "").lower()
                if host.endswith("."+h): found.add(host)
            except Exception: continue
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    verified = await bulk_check(list(found), concurrency=25)
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source("Wayback Machine CDX API + DNS verification")

RULES = [

]

@router.post("/api/recon/wayback_subdomain_extract")
async def recon_wayback_subdomain_extract(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="wayback_subdomain_extract",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
