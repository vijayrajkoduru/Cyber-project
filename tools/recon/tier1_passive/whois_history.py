"""whois_history — VL-FORGE Recon §1 Passive Footprint: Historical WHOIS via viewdns.info"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.whois_history_findings import WHOIS_HISTORY_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"https://viewdns.info/iphistory/?domain={ctx.host}", timeout=10,
            headers={'User-Agent': 'VulnusLab/1.0'})
        ctx.state['whois_history_found'] = 'IP Address' in r.text
        ctx.source('viewdns-iphistory')
    except Exception as e:
        ctx.state['whois_history_error'] = str(e)[:120]
        ctx.source('whois-history-error')

@router.post("/api/recon/whois_history")
async def recon_whois_history(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="whois_history",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
