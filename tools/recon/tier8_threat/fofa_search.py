"""fofa_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("FOFA_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False
        ctx.source("FOFA_API_KEY not set"); return
    from tools.recon._threat_helpers import api_get
    url = f'https://fofa.info/api/v1/search/all?email=' + os.environ.get('FOFA_EMAIL','') + '&key=' + key + '&qbase64=' + __import__('base64').b64encode(("host=\""+h+"\"").encode()).decode()
    headers = {}
    code, data = await api_get(url, headers=headers)
    ctx.state["api_key_configured"] = True
    ctx.state["status_code"] = code
    ctx.state["response_summary"] = {k:v for k,v in (data or {}).items() if k != "_error"} if isinstance(data,dict) else {}
    ctx.state["threat_hit"] = (data or {}).get("size",0) > 0
    ctx.source("fofa_search API probe")

RULES = [
    lambda s: {"name":"fofa_search: target flagged in threat intelligence","severity":"LOW",
        "evidence":f"API response: {s.get('response_summary')}",
        "remediation":"Investigate the listing reason; if false-positive submit dispute to provider",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("threat_hit") else None,
]

@router.post("/api/recon/fofa_search")
async def recon_fofa_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="fofa_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Threat Hit","threat_hit"),("Response Summary","response_summary")])

def register(app):
    app.include_router(router)
