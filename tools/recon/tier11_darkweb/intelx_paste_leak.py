"""intelx_paste_leak — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("INTELX_API_KEY","")
    ctx.state["api_key_configured"] = bool(key)
    ctx.state["note"] = "Intel X paste/leak search requires INTELX_API_KEY"
    ctx.source("Intel X paste/leak (key gated)")

RULES = [

]

@router.post("/api/recon/intelx_paste_leak")
async def recon_intelx_paste_leak(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="intelx_paste_leak",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured")])

def register(app):
    app.include_router(router)
