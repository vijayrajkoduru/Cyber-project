"""alienvault_otx — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("OTX_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False
        ctx.source("OTX_API_KEY not set"); return
    from tools.recon._threat_helpers import api_get
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/' + h + '/general'
    headers = {'X-OTX-API-KEY': key}
    code, data = await api_get(url, headers=headers)
    ctx.state["api_key_configured"] = True
    ctx.state["status_code"] = code
    ctx.state["response_summary"] = {k:v for k,v in (data or {}).items() if k != "_error"} if isinstance(data,dict) else {}
    ctx.state["threat_hit"] = (data or {}).get("pulse_info",{}).get("count",0) > 0
    ctx.source("alienvault_otx API probe")

RULES = [
    lambda s: {"name":"alienvault_otx: target flagged in threat intelligence","severity":"MEDIUM",
        "evidence":f"API response: {s.get('response_summary')}",
        "remediation":"Investigate the listing reason; if false-positive submit dispute to provider",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("threat_hit") else None,
]

@router.post("/api/recon/alienvault_otx")
async def recon_alienvault_otx(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="alienvault_otx",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Threat Hit","threat_hit"),("Response Summary","response_summary")])

def register(app):
    app.include_router(router)
