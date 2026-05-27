"""common_crawl — VL-FORGE Recon §1 Passive Footprint: Common Crawl URL index"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.common_crawl_findings import COMMON_CRAWL_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"http://index.commoncrawl.org/CC-MAIN-2024-51-index?url=*.{ctx.host}&output=json",
            timeout=15)
        if r.status_code == 200 and r.text.strip():
            lines = [l for l in r.text.splitlines() if l.strip()]
            ctx.state['cc_urls_total'] = len(lines)
            ctx.source(f'CC {len(lines)} URLs')
        else:
            ctx.state['cc_urls_total'] = 0
            ctx.source('CC-no-data')
    except Exception as e:
        ctx.state['cc_error'] = str(e)[:120]
        ctx.source('cc-error')

@router.post("/api/recon/common_crawl")
async def recon_common_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="common_crawl",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
