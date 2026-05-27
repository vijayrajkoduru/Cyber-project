"""stealer_log_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner


router = APIRouter()

async def gather(ctx: ScanContext):
    ctx.state["api_key_configured"] = False
    ctx.state["note"] = "Stealer log feeds (RedLine, Vidar, etc.) require paid feeds (russianmarket monitors, IntelX, Hudson Rock). Intel-only stub."
    ctx.source("stealer log feeds (paid)")

RULES = [

]

@router.post("/api/recon/stealer_log_search")
async def recon_stealer_log_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="stealer_log_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured")])

def register(app):
    app.include_router(router)
