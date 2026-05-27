"""hunter_io_email_pattern — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("HUNTER_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("HUNTER_API_KEY not set"); return
    code, d = await get_json(f"https://api.hunter.io/v2/domain-search?domain={h}&api_key={key}&limit=10")
    data = (d or {{}}).get("data",{{}}) if isinstance(d, dict) else {{}}
    emails = data.get("emails",[])
    ctx.state["api_key_configured"] = True
    ctx.state["pattern"] = data.get("pattern")
    ctx.state["emails"] = [{"value":e.get("value"),"first_name":e.get("first_name"),"position":e.get("position")} for e in emails[:15]]
    ctx.state["count"] = len(emails)
    ctx.source("Hunter.io domain-search API")

RULES = [

]

@router.post("/api/recon/hunter_io_email_pattern")
async def recon_hunter_io_email_pattern(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="hunter_io_email_pattern",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Pattern","pattern"),("Emails","emails"),("Count","count")])

def register(app):
    app.include_router(router)
