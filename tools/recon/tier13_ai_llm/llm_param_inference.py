"""llm_param_inference v3 — VL-FORGE. Key-gated; no status-as-finding."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    keyed=bool(os.environ.get("OPENAI_API_KEY","") or os.environ.get("ANTHROPIC_API_KEY",""))
    ctx.state["llm_key_configured"]=keyed
    if not keyed:
        ctx.state["skipped_reason"]="llm_param_inference: set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable parameter inference"
def _r_no_key(s):
    if s.get("llm_key_configured"): return None
    return {"name":"llm_param_inference requires LLM API key","severity":"INFO",
        "evidence":"Set ANTHROPIC_API_KEY or OPENAI_API_KEY"}
FINDING_RULES=[_r_no_key]
INTEL_FIELDS=[("LLM key","llm_key_configured")]
@router.post("/api/recon/llm_param_inference")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="llm_param_inference",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
