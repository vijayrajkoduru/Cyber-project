"""source_code_rag_llm v3 — VL-FORGE. Key-gated; no status-as-finding."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    keyed=bool(os.environ.get("OPENAI_API_KEY","") or os.environ.get("ANTHROPIC_API_KEY",""))
    ctx.state["llm_key_configured"]=keyed
    if not keyed:
        ctx.state["skipped_reason"]="source_code_rag_llm: set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable code RAG"
def _r_no_key(s):
    if s.get("llm_key_configured"): return None
    return {"name":"source_code_rag_llm requires LLM API key","severity":"INFO",
        "evidence":"Set ANTHROPIC_API_KEY or OPENAI_API_KEY"}
FINDING_RULES=[_r_no_key]
INTEL_FIELDS=[("LLM key","llm_key_configured")]
@router.post("/api/recon/source_code_rag_llm")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="source_code_rag_llm",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
