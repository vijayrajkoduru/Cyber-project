"""apple_store_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    code, d = await get_json(f"https://itunes.apple.com/search?term={urllib.parse.quote(name)}&entity=software&limit=15")
    results = (d or {{}}).get("results",[]) if isinstance(d,dict) else []
    ctx.state["apps_found"] = [{"id":r.get("trackId"),"name":r.get("trackName"),"bundle":r.get("bundleId"),"seller":r.get("sellerName")} for r in results[:15]]
    ctx.state["count"] = len(results)
    ctx.source("iTunes Search API (no auth)")

RULES = [

]

@router.post("/api/recon/apple_store_search")
async def recon_apple_store_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="apple_store_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Apps Found","apps_found"),("Count","count")])

def register(app):
    app.include_router(router)
