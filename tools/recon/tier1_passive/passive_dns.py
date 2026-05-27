"""passive_dns — VL-FORGE Recon §1 Passive Footprint: Passive DNS via HackerTarget"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.passive_dns_findings import PASSIVE_DNS_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"https://api.hackertarget.com/hostsearch/?q={ctx.host}", timeout=10)
        if r.status_code == 200 and 'error' not in r.text.lower():
            entries = [l.strip() for l in r.text.splitlines() if l.strip()]
            ctx.state['passive_dns_total'] = len(entries)
            ctx.state['passive_dns_sample'] = ', '.join(entries[:5])
            ctx.source(f'HackerTarget {len(entries)} records')
    except Exception as e:
        ctx.state['passive_dns_error'] = str(e)[:120]
        ctx.source('passive-dns-error')

@router.post("/api/recon/passive_dns")
async def recon_passive_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="passive_dns",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
