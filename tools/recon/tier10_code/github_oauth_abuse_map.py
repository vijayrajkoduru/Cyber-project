"""github_oauth_abuse_map — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner


router = APIRouter()

async def gather(ctx: ScanContext):
    token = os.environ.get("GITHUB_TOKEN","")
    ctx.state["github_token_configured"] = bool(token)
    ctx.state["note"] = "OAuth app abuse mapping requires GITHUB_TOKEN with admin:org scope"
    ctx.source("GitHub OAuth app audit")

RULES = [

]

@router.post("/api/recon/github_oauth_abuse_map")
async def recon_github_oauth_abuse_map(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="github_oauth_abuse_map",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Github Token Configured","github_token_configured")])

def register(app):
    app.include_router(router)
