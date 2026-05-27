"""trademark_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    code, t = await get_text(f"https://tmsearch.uspto.gov/search/search-information?searchText={urllib.parse.quote(name)}")
    ctx.state["accessible"] = code == 200
    ctx.state["note"] = "USPTO TESS requires session; pure intel result only"
    ctx.source("USPTO TESS probe")

RULES = [

]

@router.post("/api/recon/trademark_search")
async def recon_trademark_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="trademark_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Accessible","accessible")])

def register(app):
    app.include_router(router)
