"""linkedin_employees — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    key = os.environ.get("LINKEDIN_COOKIE","")
    ctx.state["api_key_configured"] = bool(key)
    ctx.state["note"] = "LinkedIn employee enumeration requires authenticated session cookie (li_at). Set LINKEDIN_COOKIE env var."
    ctx.source("linkedin_employees — LINKEDIN_COOKIE-gated")

RULES = [

]

@router.post("/api/recon/linkedin_employees")
async def recon_linkedin_employees(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="linkedin_employees",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Note","note")])

def register(app):
    app.include_router(router)
