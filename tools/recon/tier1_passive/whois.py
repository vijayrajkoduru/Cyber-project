"""whois — VL-FORGE Recon §1 Passive Footprint: python-whois lookup"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import whois as pywhois
try:
    from tools._payloads.whois_findings import WHOIS_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        w = await asyncio.to_thread(pywhois.whois, ctx.host)
        ctx.state['registrar'] = str(w.registrar or '')
        ctx.state['created'] = str(w.creation_date or '')
        ctx.state['expires'] = str(w.expiration_date or '')
        ctx.state['whois_found'] = bool(w.registrar)
        ctx.source('python-whois')
    except Exception as e:
        ctx.state['whois_error'] = str(e)[:120]
        ctx.source('whois-error')

@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="whois",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
