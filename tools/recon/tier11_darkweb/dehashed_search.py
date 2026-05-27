"""dehashed_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json, base64

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    email = os.environ.get("DEHASHED_EMAIL","")
    key   = os.environ.get("DEHASHED_API_KEY","")
    if not (email and key):
        ctx.state["api_key_configured"] = False; ctx.source("DEHASHED_EMAIL/API_KEY not set"); return
    entries = 0
    try:
        auth = base64.b64encode(f"{email}:{key}".encode()).decode()
        def _q():
            req = urllib.request.Request(f"https://api.dehashed.com/search?query=domain:{h}",
                headers={"Authorization":f"Basic {auth}","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
        d = await asyncio.to_thread(_q)
        entries = d.get("total",0)
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["api_key_configured"] = True
    ctx.state["leaked_entries"] = entries
    ctx.source("DeHashed credential search by domain")

RULES = [
    lambda s: {"name":"Leaked credentials for domain in DeHashed","severity":"HIGH",
        "evidence":f"{s.get('leaked_entries')} entries in DeHashed",
        "remediation":"Force password reset for all affected emails. Audit MFA enrollment.",
        "cwe":"CWE-359","owasp":"A07:2021"
    } if s.get("leaked_entries",0) > 0 else None,
]

@router.post("/api/recon/dehashed_search")
async def recon_dehashed_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dehashed_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Leaked Entries","leaked_entries")])

def register(app):
    app.include_router(router)
