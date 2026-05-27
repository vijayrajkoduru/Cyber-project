"""cert_san_aggregator — VL-FORGE Recon §1 Passive Footprint: Active certificate SAN aggregation (⭐ NEW)"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.cert_san_aggregator_findings import CERT_SAN_AGGREGATOR_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain=%25.{ctx.host}&output=json", timeout=15)
        if r.status_code == 200 and r.text.strip():
            certs = r.json()
            sans = set()
            for c in certs:
                for d in (c.get('name_value','') or '').split('\n'):
                    d = d.strip().lower()
                    if d and '*' not in d:
                        sans.add(d)
            ctx.state['ct_san_total'] = len(sans)
            ctx.state['ct_san_sample'] = list(sans)[:20]
            ctx.source(f'crt.sh {len(sans)} unique SANs')
        else:
            ctx.source('crt-san-no-data')
    except Exception as e:
        ctx.state['cert_san_error'] = str(e)[:120]
        ctx.source('cert-san-error')

@router.post("/api/recon/cert_san_aggregator")
async def recon_cert_san_aggregator(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cert_san_aggregator",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
