"""cloud_function_url_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    found = []
    # Lambda function URLs follow https://<id>.lambda-url.<region>.on.aws — can't enumerate without id
    # Cloud Run is more guessable
    for tpl in (f"https://{base_name}.run.app/", f"https://{base_name}-uc.a.run.app/"):
        c, _, _ = await fetch(tpl, timeout=4)
        if c and c != 404: found.append({"url":tpl,"status":c})
    ctx.state["discovered"] = found
    ctx.source("GCP Cloud Run URL permutation")

RULES = [

]

@router.post("/api/recon/cloud_function_url_enum")
async def recon_cloud_function_url_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cloud_function_url_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
