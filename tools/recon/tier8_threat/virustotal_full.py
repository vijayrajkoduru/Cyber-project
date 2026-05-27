"""virustotal_full — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("VIRUSTOTAL_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False
        ctx.source("VIRUSTOTAL_API_KEY not set"); return
    from tools.recon._threat_helpers import api_get
    url = f'https://www.virustotal.com/api/v3/domains/' + h
    headers = {'x-apikey': key}
    code, data = await api_get(url, headers=headers)
    ctx.state["api_key_configured"] = True
    ctx.state["status_code"] = code
    ctx.state["response_summary"] = {k:v for k,v in (data or {}).items() if k != "_error"} if isinstance(data,dict) else {}
    ctx.state["threat_hit"] = (data or {}).get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0) > 0
    ctx.source("virustotal_full API probe")

RULES = [
    lambda s: {"name":"virustotal_full: target flagged in threat intelligence","severity":"HIGH",
        "evidence":f"API response: {s.get('response_summary')}",
        "remediation":"Investigate the listing reason; if false-positive submit dispute to provider",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("threat_hit") else None,
]

@router.post("/api/recon/virustotal_full")
async def recon_virustotal_full(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="virustotal_full",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Threat Hit","threat_hit"),("Response Summary","response_summary")])

def register(app):
    app.include_router(router)
