"""ai_wordlist_subdomain — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import pathlib

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    for p in ("/app/tools/_payloads/recon/ai_subs.txt","tools/_payloads/recon/ai_subs.txt"):
        wlp = pathlib.Path(p)
        if wlp.exists(): break
    if not wlp.exists():
        ctx.state["wordlist_loaded"] = False
        ctx.source("AI subdomain wordlist not found"); return
    words = [w.strip() for w in wlp.read_text(encoding="utf-8",errors="ignore").splitlines() if w.strip() and not w.startswith("#")][:300]
    candidates = [f"{w}.{h}" for w in words]
    found = await bulk_check(candidates, concurrency=25)
    ctx.state["wordlist_size"] = len(words)
    ctx.state["wordlist_loaded"] = True
    ctx.state["discovered"] = found
    ctx.state["count"] = len(found)
    ctx.source(f"AI-curated wordlist ({len(words)} probed)")

RULES = [

]

@router.post("/api/recon/ai_wordlist_subdomain")
async def recon_ai_wordlist_subdomain(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ai_wordlist_subdomain",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Wordlist Size","wordlist_size"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
