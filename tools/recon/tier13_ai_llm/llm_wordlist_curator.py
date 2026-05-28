"""llm_wordlist_curator v2 — VL-FORGE."""
import os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    ctx.state["llm_key_configured"]=bool(os.environ.get("OPENAI_API_KEY","") or os.environ.get("ANTHROPIC_API_KEY",""))
def _r_no_key(s):
    if s.get("llm_key_configured"): return None
    return {"name":"llm_wordlist_curator requires LLM API key","severity":"INFO","evidence":"OPENAI_API_KEY or ANTHROPIC_API_KEY"}
def _r_ready(s):
    if not s.get("llm_key_configured"): return None
    return {"name":"llm_wordlist_curator ready","severity":"INFO","evidence":"LLM-generated wordlists on demand"}
FINDING_RULES=[_r_no_key,_r_ready]
INTEL_FIELDS=[("LLM key","llm_key_configured")]
@router.post("/api/recon/llm_wordlist_curator")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="llm_wordlist_curator",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
