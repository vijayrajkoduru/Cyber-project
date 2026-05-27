"""reverse_ip — VL-FORGE Recon §1 Passive Footprint: Sibling domains via HackerTarget"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import socket
try:
    from tools._payloads.reverse_ip_findings import REVERSE_IP_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, ctx.host)
        ctx.state['ip'] = ip
        r = await asyncio.to_thread(requests.get,
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        if r.status_code == 200 and 'error' not in r.text.lower():
            siblings = [s.strip() for s in r.text.splitlines() if s.strip() and s.strip() != ctx.host]
            ctx.state['siblings_total'] = len(siblings)
            ctx.state['sibling_sample'] = ', '.join(siblings[:5])
            ctx.source(f'HackerTarget {len(siblings)} siblings')
    except Exception as e:
        ctx.state['reverse_ip_error'] = str(e)[:120]
        ctx.source('reverse-ip-error')

@router.post("/api/recon/reverse_ip")
async def recon_reverse_ip(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="reverse_ip",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
