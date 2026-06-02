"""llm_wordlist_curator v3 - VL-FORGE - Claude-generated content-discovery wordlist.

Generates a target-tailored directory/file wordlist for downstream content
discovery (gobuster/ffuf). Pure generator: it makes NO claim about the target's
live state (zero false positives) - it only exposes AI-curated candidates as
intel. Degrades to a clean SKIPPED when ANTHROPIC_API_KEY is unset.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.recon._llm import ask_claude_list_async, llm_available

router = APIRouter()


async def gather(ctx):
    host = str(ctx.host)
    ctx.state["llm_configured"] = llm_available()
    if not llm_available():
        ctx.state["skipped_reason"] = (
            "llm_wordlist_curator: set ANTHROPIC_API_KEY to enable AI-curated wordlist generation")
        return
    prompt = (
        f"You are assisting authorized recon of '{host}'. Generate a focused wordlist of up to 80 "
        "directory and file path candidates (NO leading slash) useful for content discovery on this "
        "site: framework defaults, backup/config file names, API route stubs, admin paths. Return "
        "ONLY a JSON array of strings. No prose.")
    words = await ask_claude_list_async(prompt, max_tokens=1200, cap=80)
    ctx.state["wordlist"] = words
    ctx.state["wordlist_count"] = len(words)
    if words:
        ctx.source("claude")


FINDING_RULES = []
INTEL_FIELDS = [("LLM configured", "llm_configured"), ("Wordlist size", "wordlist_count")]


@router.post("/api/recon/llm_wordlist_curator")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="llm_wordlist_curator",
                             gather_func=gather, finding_rules=FINDING_RULES,
                             intel_fields=INTEL_FIELDS, flat_field_keys=["wordlist"])


def register(app):
    app.include_router(router)
