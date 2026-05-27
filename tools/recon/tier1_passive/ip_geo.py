"""ip_geo — VL-FORGE Recon §1 Passive Footprint: ipinfo.io geolocation"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import socket
try:
    from tools._payloads.ip_geo_findings import IP_GEO_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, ctx.host)
        ctx.state['ip'] = ip
        r = await asyncio.to_thread(requests.get, f"https://ipinfo.io/{ip}/json", timeout=8)
        if r.status_code == 200:
            d = r.json()
            ctx.state['country'] = d.get('country', '')
            ctx.state['city'] = d.get('city', '')
            ctx.state['org'] = d.get('org', '')
            ctx.state['ip_geo_found'] = True
            ctx.source(f"ipinfo {d.get('country','?')}/{d.get('city','?')}")
    except Exception as e:
        ctx.state['ip_geo_error'] = str(e)[:120]
        ctx.source('ip-geo-error')

@router.post("/api/recon/ip_geo")
async def recon_ip_geo(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ip_geo",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
