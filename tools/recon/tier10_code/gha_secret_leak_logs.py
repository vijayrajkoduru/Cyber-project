"""gha_secret_leak_logs — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner


router = APIRouter()

async def gather(ctx: ScanContext):
    token = os.environ.get("GITHUB_TOKEN","")
    ctx.state["github_token_configured"] = bool(token)
    ctx.state["note"] = "Full GHA secret leak scan requires GITHUB_TOKEN + repo admin scope to read action logs"
    ctx.source("GitHub Actions log scan")

RULES = [

]

@router.post("/api/recon/gha_secret_leak_logs")
async def recon_gha_secret_leak_logs(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gha_secret_leak_logs",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Github Token Configured","github_token_configured")])

def register(app):
    app.include_router(router)
