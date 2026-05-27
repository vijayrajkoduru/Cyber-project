"""vercel_netlify — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    found = []
    for tpl, platform in [(f"{base_name}.vercel.app","Vercel"), (f"{base_name}.netlify.app","Netlify"),
                          (f"{base_name}.pages.dev","Cloudflare Pages")]:
        c, _, _ = await fetch(f"https://{tpl}/", timeout=4)
        if c and c != 404: found.append({"hostname":tpl,"platform":platform,"status":c})
    ctx.state["discovered"] = found
    ctx.source("Vercel/Netlify/CF-Pages hostname check")

RULES = [

]

@router.post("/api/recon/vercel_netlify")
async def recon_vercel_netlify(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="vercel_netlify",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
