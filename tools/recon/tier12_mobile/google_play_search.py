"""google_play_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    code, t = await get_text(f"https://play.google.com/store/search?q={urllib.parse.quote(name)}&c=apps&hl=en")
    if code != 200:
        ctx.state["search_accessible"] = False; ctx.source("Play Store search unreachable"); return
    apps = list(set(re.findall(r"/store/apps/details\?id=([a-zA-Z0-9._-]+)", t)))[:15]
    ctx.state["search_accessible"] = True
    ctx.state["apps_found"] = apps
    ctx.state["count"] = len(apps)
    ctx.source("Google Play Store HTML search")

RULES = [

]

@router.post("/api/recon/google_play_search")
async def recon_google_play_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="google_play_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Apps Found","apps_found"),("Count","count")])

def register(app):
    app.include_router(router)
