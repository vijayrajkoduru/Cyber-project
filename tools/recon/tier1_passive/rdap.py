"""rdap — VL-FORGE Recon §1 Passive Footprint: Modern WHOIS via rdap.org"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.rdap_findings import RDAP_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get, f"https://rdap.org/domain/{ctx.host}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            ctx.state['rdap_handle'] = d.get('handle', '')
            ctx.state['rdap_status'] = ', '.join(d.get('status', []))
            ctx.state['rdap_found'] = True
            ctx.source('rdap.org')
        else:
            ctx.state['rdap_found'] = False
            ctx.source('rdap-no-data')
    except Exception as e:
        ctx.state['rdap_error'] = str(e)[:120]
        ctx.source('rdap-error')

@router.post("/api/recon/rdap")
async def recon_rdap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="rdap",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
