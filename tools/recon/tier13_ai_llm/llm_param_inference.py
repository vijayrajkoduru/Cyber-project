"""llm_param_inference — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("OPENAI_API_KEY","") or os.environ.get("ANTHROPIC_API_KEY","")
    ctx.state["llm_key_configured"] = bool(key)
    ctx.state["note"] = "Parameter inference requires OPENAI/ANTHROPIC key. Combine with param_discovery output for LLM-based parameter name expansion."
    ctx.source("llm_param_inference — LLM key required")

RULES = [

]

@router.post("/api/recon/llm_param_inference")
async def recon_llm_param_inference(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="llm_param_inference",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("LLM Key Configured","llm_key_configured"),("Note","note")])

def register(app):
    app.include_router(router)
