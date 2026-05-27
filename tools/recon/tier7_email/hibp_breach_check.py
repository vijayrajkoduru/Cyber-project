"""hibp_breach_check — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("HIBP_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("HIBP_API_KEY not set"); return
    code, d = await get_json(f"https://haveibeenpwned.com/api/v3/breaches?domain={h}",
                             headers={"hibp-api-key":key,"User-Agent":"VulnusLab"})
    breaches = d if isinstance(d, list) else []
    ctx.state["api_key_configured"] = True
    ctx.state["breach_count"] = len(breaches)
    ctx.state["breaches"] = [{"name":b.get("Name"),"date":b.get("BreachDate"),"pwn_count":b.get("PwnCount")} for b in breaches[:10]]
    ctx.source("HIBP domain breach API")

RULES = [
    lambda s: {"name":"Domain has appeared in HIBP breach corpus","severity":"HIGH",
        "evidence":f"{s.get('breach_count')} breaches: {[b.get('name') for b in s.get('breaches',[])[:5]]}",
        "remediation":"Force password reset for affected users. Audit MFA. Subscribe to HIBP domain notifications.",
        "cwe":"CWE-359","owasp":"A07:2021"
    } if s.get("breach_count",0) > 0 else None,
]

@router.post("/api/recon/hibp_breach_check")
async def recon_hibp_breach_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="hibp_breach_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Breach Count","breach_count"),("Breaches","breaches")])

def register(app):
    app.include_router(router)
