"""wayback_timeline — VL-FORGE Recon §1 Passive Footprint: Wayback Machine snapshot count"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.wayback_timeline_findings import WAYBACK_TIMELINE_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"http://web.archive.org/cdx/search/cdx?url={ctx.host}&output=json&limit=1000",
            timeout=15)
        if r.status_code == 200 and r.text.strip():
            data = r.json()
            count = max(0, len(data) - 1)
            ctx.state['wayback_snapshots'] = count
            if count > 0:
                ctx.state['wayback_first'] = data[1][1]
                ctx.state['wayback_last'] = data[-1][1]
            ctx.source(f'archive.org {count} snapshots')
    except Exception as e:
        ctx.state['wayback_error'] = str(e)[:120]
        ctx.source('wayback-error')

@router.post("/api/recon/wayback_timeline")
async def recon_wayback_timeline(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="wayback_timeline",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
