"""gha_runner_disco — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    # Lightweight: we'd need GITHUB_TOKEN for full org enum; signal intel only
    token = os.environ.get("GITHUB_TOKEN","")
    ctx.state["github_token_configured"] = bool(token)
    ctx.state["note"] = "Full self-hosted-runner enumeration requires GITHUB_TOKEN + org-admin scope; otherwise pure intel."
    ctx.source("GHA self-hosted runner discovery (needs token)")

RULES = [

]

@router.post("/api/recon/gha_runner_disco")
async def recon_gha_runner_disco(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gha_runner_disco",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Github Token Configured","github_token_configured")])

def register(app):
    app.include_router(router)
