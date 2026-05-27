"""crt_search — VL-FORGE Recon §1 Passive Footprint: CT log search via crt.sh"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

try:
    from tools._payloads.crt_search_findings import CRT_SEARCH_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        r = await asyncio.to_thread(requests.get,
            f"https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain=%25.{ctx.host}&output=json&exclude=expired", timeout=15)
        if r.status_code == 200 and r.text.strip():
            certs = r.json()
            domains = sorted({c.get('common_name','').lower() for c in certs if c.get('common_name')})
            ctx.state['ct_certs_total'] = len(certs)
            ctx.state['ct_domains'] = list(domains)[:20]
            ctx.source(f'crt.sh {len(certs)} certs')
        else:
            ctx.source('crt-no-data')
    except Exception as e:
        ctx.state['crt_error'] = str(e)[:120]
        ctx.source('crt-error')

@router.post("/api/recon/crt_search")
async def recon_crt_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="crt_search",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
