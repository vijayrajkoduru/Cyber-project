"""youtube_channel — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    key = os.environ.get("YOUTUBE_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("YOUTUBE_API_KEY not set"); return
    code, d = await get_json(f"https://www.googleapis.com/youtube/v3/search?part=snippet&q={urllib.parse.quote(name)}&type=channel&key={key}")
    items = (d or {{}}).get("items",[]) if isinstance(d, dict) else []
    ctx.state["api_key_configured"] = True
    ctx.state["channels"] = [{"id":i.get("id",{{}}).get("channelId"),"title":i.get("snippet",{{}}).get("channelTitle")} for i in items[:10]]
    ctx.source("YouTube Data API v3 — channel search")

RULES = [

]

@router.post("/api/recon/youtube_channel")
async def recon_youtube_channel(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="youtube_channel",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Channels","channels")])

def register(app):
    app.include_router(router)
