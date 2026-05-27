"""tech_stack_detect — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, body = await fetch(url)
    tech = []
    txt = body.decode("utf-8","ignore").lower()
    sigs = {
        "WordPress":["wp-content","wp-includes","wp-json"],
        "Drupal":["drupal.settings","sites/default/files"],
        "Joomla":["joomla","com_content"],
        "Magento":["mage/cookies","static/version"],
        "Shopify":["cdn.shopify.com"],
        "Laravel":["laravel_session","x-csrf-token"],
        "Django":["csrftoken","__admin"],
        "Rails":["rails-ujs","x-runtime"],
        "Next.js":["__next_data","_next/static"],
        "React":["data-reactroot","react-dom"],
        "Vue.js":["__vue__","vuejs"],
        "Angular":["ng-version","ng-app"],
        "Express":[hdrs.get("X-Powered-By","").lower()],
        "Cloudflare":["__cf_bm","cf-ray"],
        "AWS":["aws-amplify","amazonaws.com"],
    }
    for name, marks in sigs.items():
        if any(m and m in txt for m in marks): tech.append(name)
        if any(m and m in str(hdrs).lower() for m in marks): tech.append(name)
    ctx.state["technologies"] = sorted(set(tech))
    ctx.source("HTML + header fingerprint")

RULES = [

]

@router.post("/api/recon/tech_stack_detect")
async def recon_tech_stack_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="tech_stack_detect",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Technologies","technologies")])

def register(app):
    app.include_router(router)
