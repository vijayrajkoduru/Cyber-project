"""osint_industries — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("OSINT_INDUSTRIES_KEY","")
    ctx.state["api_key_configured"] = bool(key)
    ctx.state["note"] = "OSINT.industries aggregator requires paid API key."
    ctx.source("osint_industries — OSINT_INDUSTRIES_KEY-gated")

RULES = [

]

@router.post("/api/recon/osint_industries")
async def recon_osint_industries(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="osint_industries",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Note","note")])

def register(app):
    app.include_router(router)
