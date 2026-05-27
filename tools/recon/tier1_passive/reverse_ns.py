"""reverse_ns — VL-FORGE Recon §1 Passive Footprint: Domains on same NS via HackerTarget"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import dns.resolver
try:
    from tools._payloads.reverse_ns_findings import REVERSE_NS_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        ns_records = await asyncio.to_thread(
            lambda: list(dns.resolver.resolve(ctx.host, 'NS', lifetime=5)))
        ns = str(ns_records[0]).rstrip('.') if ns_records else ''
        ctx.state['ns'] = ns
        if ns:
            r = await asyncio.to_thread(requests.get,
                f"https://api.hackertarget.com/reversens/?q={ns}", timeout=10)
            if r.status_code == 200 and 'error' not in r.text.lower():
                others = [s.strip() for s in r.text.splitlines() if s.strip() and s.strip() != ctx.host]
                ctx.state['ns_siblings_total'] = len(others)
                ctx.source(f'HackerTarget {len(others)} on {ns}')
    except Exception as e:
        ctx.state['reverse_ns_error'] = str(e)[:120]
        ctx.source('reverse-ns-error')

@router.post("/api/recon/reverse_ns")
async def recon_reverse_ns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="reverse_ns",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
