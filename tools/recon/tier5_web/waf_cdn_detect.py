"""waf_cdn_detect — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, body = await fetch(url)
    lh = {k.lower(): v for k,v in hdrs.items()}
    fingerprints = []
    sigs = {
        "Cloudflare":["cf-ray","cf-cache-status","__cf_bm"],
        "AWS CloudFront":["x-amz-cf-id","x-amz-cf-pop"],
        "Akamai":["x-akamai","akamai-request-id","x-akamai-staging"],
        "Fastly":["x-fastly","fastly-debug"],
        "Sucuri":["x-sucuri-id","x-sucuri-cache"],
        "Imperva/Incapsula":["x-iinfo","x-cdn"],
        "Azure CDN":["x-azure-ref","x-msedge-ref"],
        "AWS WAF":["x-amzn-requestid"],
        "F5 BIG-IP":["x-waf","bigipserver"],
    }
    text = " ".join(f"{k}:{v}" for k,v in lh.items()).lower()
    for name, marks in sigs.items():
        if any(m in text for m in marks): fingerprints.append(name)
    ctx.state["fingerprints"] = sorted(set(fingerprints))
    ctx.state["detected"] = bool(fingerprints)
    ctx.source("Header fingerprint — 9 WAF/CDN providers")

RULES = [
    ]

@router.post("/api/recon/waf_cdn_detect")
async def recon_waf_cdn_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="waf_cdn_detect",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Fingerprints","fingerprints"),("Detected","detected")])

def register(app):
    app.include_router(router)
