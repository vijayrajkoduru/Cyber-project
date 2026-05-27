"""domain_age — VL-FORGE Recon §1 Passive Footprint: Domain age via whois creation date"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import whois as pywhois
from datetime import datetime
try:
    from tools._payloads.domain_age_findings import DOMAIN_AGE_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        w = await asyncio.to_thread(pywhois.whois, ctx.host)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd:
            age = (datetime.utcnow() - cd).days
            ctx.state['domain_age_days'] = age
            ctx.state['domain_age_years'] = round(age/365.25, 2)
            ctx.state['created'] = str(cd)
            ctx.source(f'created {cd}')
        else:
            ctx.source('no-creation-date')
    except Exception as e:
        ctx.state['domain_age_error'] = str(e)[:120]
        ctx.source('domain-age-error')

@router.post("/api/recon/domain_age")
async def recon_domain_age(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="domain_age",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
