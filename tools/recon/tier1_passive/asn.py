"""asn — VL-FORGE Recon §1 Passive Footprint: ASN + IP block via BGPView"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import socket
try:
    from tools._payloads.asn_findings import ASN_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, ctx.host)
        ctx.state['ip'] = ip
        r = await asyncio.to_thread(requests.get, f"https://api.bgpview.io/ip/{ip}", timeout=8)
        if r.status_code == 200:
            d = r.json().get('data', {})
            prefixes = d.get('prefixes', [])
            if prefixes:
                p = prefixes[0]
                ctx.state['asn'] = p.get('asn', {}).get('asn', '')
                ctx.state['asn_name'] = p.get('asn', {}).get('name', '')
                ctx.state['asn_found'] = True
                # Detect Cloudflare-fronted target (suppress noise INFO findings)
        _cf = False
        try:
            import dns.resolver as _r
            ns = [str(x).lower() for x in _r.resolve(ctx.host, "NS", lifetime=4)]
            _cf = any("cloudflare" in n for n in ns)
        except Exception: pass
        ctx.state["_cloudflare_detected"] = _cf
        ctx.source('BGPView')
    except Exception as e:
        ctx.state['asn_error'] = str(e)[:120]
        ctx.source('asn-error')

@router.post("/api/recon/asn")
async def recon_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="asn",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
