"""vercel_netlify — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
from tools.recon._targeting import get_org_name, can_do_osint


router = APIRouter()

# Generic names that collide with someone else's actual Vercel/Netlify project.
# 'app.vercel.app' / 'app.netlify.app' exist and are not the customer's.
_GENERIC_NAMES = frozenset({
    "app","api","www","web","dev","staging","test","demo","admin",
    "portal","site","shop","blog","mail","cdn","static","assets",
    "main","home","index",
})

async def gather(ctx: ScanContext):
    # ZERO-FP-V1: probe the customer's BRAND name on PaaS providers, not
    # the subdomain label. Previously 'app.vulnuslab.com' probed for
    # 'app.netlify.app' which exists as Netlify's own marketing page.
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="not applicable for IP / internal hostname"
        return
    base_name = get_org_name(ctx.host) or ""
    if not base_name or base_name.lower() in _GENERIC_NAMES or len(base_name) < 4:
        ctx.state["skipped_reason"]=f"Brand name '{base_name}' too generic to probe PaaS namespaces without false-positive risk"
        return
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
