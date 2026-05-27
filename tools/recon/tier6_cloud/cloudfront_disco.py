"""cloudfront_disco — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    c, hdrs, _ = await fetch(base)
    cf = "cloudfront" in str(hdrs).lower() or "x-amz-cf-id" in {k.lower() for k in hdrs}
    ctx.state["cloudfront_detected"] = cf
    ctx.state["evidence_headers"] = {k:v for k,v in hdrs.items() if "amz" in k.lower() or "cloudfront" in k.lower()}
    ctx.source("CloudFront header fingerprint")

RULES = [

]

@router.post("/api/recon/cloudfront_disco")
async def recon_cloudfront_disco(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cloudfront_disco",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Cloudfront Detected","cloudfront_detected"),("Evidence Headers","evidence_headers")])

def register(app):
    app.include_router(router)
