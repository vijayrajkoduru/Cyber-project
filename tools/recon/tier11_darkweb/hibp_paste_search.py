"""hibp_paste_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("HIBP_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("HIBP_API_KEY not set"); return
    breaches = []
    try:
        def _q():
            req = urllib.request.Request(f"https://haveibeenpwned.com/api/v3/breaches?domain={h}",
                headers={"hibp-api-key":key,"User-Agent":"VulnusLab"})
            with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
        d = await asyncio.to_thread(_q)
        breaches = d if isinstance(d, list) else []
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["api_key_configured"] = True
    ctx.state["breaches"] = [{"name":b.get("Name"),"date":b.get("BreachDate"),"pwn_count":b.get("PwnCount")} for b in breaches[:10]]
    ctx.state["breach_count"] = len(breaches)
    ctx.source("HIBP breaches API for domain")

RULES = [
    lambda s: {"name":"Domain has appeared in public data breaches","severity":"HIGH",
        "evidence":f"{s.get('breach_count')} breaches: {[b['name'] for b in s.get('breaches',[])[:5]]}",
        "remediation":"Force password reset for affected accounts. Enable MFA. Audit credential reuse via password manager logs.",
        "cwe":"CWE-359","owasp":"A07:2021"
    } if s.get("breach_count",0) > 0 else None,
]

@router.post("/api/recon/hibp_paste_search")
async def recon_hibp_paste_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="hibp_paste_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Breaches","breaches"),("Breach Count","breach_count")])

def register(app):
    app.include_router(router)
