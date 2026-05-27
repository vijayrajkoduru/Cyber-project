"""mobile_backend_shodan — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("SHODAN_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False; ctx.source("SHODAN_API_KEY not set"); return
    name = ctx.host.split(".")[0]
    code, d = await get_json(f"https://api.shodan.io/shodan/host/search?key={key}&query=hostname:{name}+http.title:%22api%22")
    matches = (d or {{}}).get("matches",[]) if isinstance(d, dict) else []
    ctx.state["api_key_configured"] = True
    ctx.state["candidates"] = [{"ip":m.get("ip_str"),"port":m.get("port"),"title":m.get("http",{{}}).get("title","")[:80]} for m in matches[:10]]
    ctx.source("Shodan — mobile-backend pattern search")

RULES = [

]

@router.post("/api/recon/mobile_backend_shodan")
async def recon_mobile_backend_shodan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="mobile_backend_shodan",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Candidates","candidates")])

def register(app):
    app.include_router(router)
