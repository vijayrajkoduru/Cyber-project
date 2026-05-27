"""gcp_app_engine — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    candidates = [f"{base_name}.appspot.com", f"{base_name}.uc.r.appspot.com", f"{base_name}-prod.appspot.com"]
    found = []
    for hn in candidates:
        c, _, _ = await fetch(f"https://{hn}/", timeout=4)
        if c and c != 404: found.append({"hostname":hn,"status":c})
    ctx.state["discovered"] = found
    ctx.source("GCP App Engine hostname permutation")

RULES = [

]

@router.post("/api/recon/gcp_app_engine")
async def recon_gcp_app_engine(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gcp_app_engine",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
