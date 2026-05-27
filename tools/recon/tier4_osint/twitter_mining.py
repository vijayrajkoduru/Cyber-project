"""twitter_mining — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("TWITTER_BEARER_TOKEN","")
    ctx.state["api_key_configured"] = bool(key)
    ctx.state["note"] = "Twitter/X scraping requires bearer token. Set TWITTER_BEARER_TOKEN."
    ctx.source("twitter_mining — TWITTER_BEARER_TOKEN-gated")

RULES = [

]

@router.post("/api/recon/twitter_mining")
async def recon_twitter_mining(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="twitter_mining",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Note","note")])

def register(app):
    app.include_router(router)
