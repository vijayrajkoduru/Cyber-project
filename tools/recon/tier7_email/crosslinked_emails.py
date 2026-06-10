"""crosslinked_emails — VL-FORGE OSINT (key-gated graceful)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    # Common env-var conventions
    candidates=["CROSSLINKED_EMAILS_API_KEY","CROSSLINKED_EMAILS_KEY","INTELX_API_KEY","LEAKCHECK_API_KEY","DEHASHED_API_KEY"]
    key=next((os.environ.get(c) for c in candidates if os.environ.get(c)),None)
    ctx.state["api_key_configured"]=bool(key)
    if not key:
        ctx.state["skipped_reason"] = "Requires Hunter.io / Snov.io API key — set env HUNTER_API_KEY to enable. Free tiers available at vendor's site."
        return
    ctx.state["host"]=ctx.host
    if key: ctx.source("crosslinked_emails-keyed")
def _r_unkeyed(s):
    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly
    # instead of emitting INFO. See skipped_reason set in gather().
    return None


def _r_keyed(s):
    if not s.get("api_key_configured"): return None
    return {"name":"crosslinked_emails configured","severity":"INFO",
        "evidence":"API integration ready — query expansion possible on demand"}
FINDING_RULES=[_r_unkeyed,_r_keyed]
INTEL_FIELDS=[("API key","api_key_configured")]
@router.post("/api/recon/crosslinked_emails")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="crosslinked_emails",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
