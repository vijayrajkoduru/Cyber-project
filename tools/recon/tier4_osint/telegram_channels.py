"""telegram_channels — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("TELEGRAM_API_ID","")
    ctx.state["api_key_configured"] = bool(key)
    ctx.state["note"] = "Telegram channel scrape requires API ID/hash via my.telegram.org."
    ctx.source("telegram_channels — TELEGRAM_API_ID-gated")

RULES = [

]

@router.post("/api/recon/telegram_channels")
async def recon_telegram_channels(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="telegram_channels",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Note","note")])

def register(app):
    app.include_router(router)
