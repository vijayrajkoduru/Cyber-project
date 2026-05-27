"""favicon_hash — VL-FORGE Recon §1 Passive Footprint: Favicon mmh3 hash for Shodan pivot"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import base64
try:
    import mmh3
except ImportError:
    mmh3 = None
try:
    from tools._payloads.favicon_hash_findings import FAVICON_HASH_FINDING_RULES as RULES
except ImportError:
    RULES = []

router = APIRouter()

async def gather(ctx: ScanContext):
    try:
        for scheme in ('https', 'http'):
            try:
                r = await asyncio.to_thread(requests.get,
                    f"{scheme}://{ctx.host}/favicon.ico", timeout=6, verify=False)
                if r.status_code == 200 and r.content:
                    ctx.state['favicon_found'] = True
                    ctx.state['favicon_size'] = len(r.content)
                    ctx.state['favicon_scheme'] = scheme
                    if mmh3:
                        ctx.state['favicon_mmh3'] = mmh3.hash(base64.encodebytes(r.content))
                    ctx.source(f'{scheme}://favicon.ico {len(r.content)}B')
                    return
            except Exception:
                continue
        ctx.state['favicon_found'] = False
        ctx.source('no-favicon')
    except Exception as e:
        ctx.state['favicon_error'] = str(e)[:120]
        ctx.source('favicon-error')

@router.post("/api/recon/favicon_hash")
async def recon_favicon_hash(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="favicon_hash",
                              gather_func=gather, finding_rules=RULES, intel_fields=[])

def register(app):
    app.include_router(router)
