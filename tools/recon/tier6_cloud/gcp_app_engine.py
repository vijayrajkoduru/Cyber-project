"""gcp_app_engine — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
from tools.recon._targeting import get_org_name, can_do_osint


router = APIRouter()

_GENERIC_NAMES = frozenset({
    "app","api","www","web","dev","staging","test","demo","admin",
    "portal","site","shop","blog","mail","cdn","static","assets",
    "main","home","index",
})

async def gather(ctx: ScanContext):
    # ZERO-FP-V1: use customer's brand name, not subdomain. Previously
    # 'app.vulnuslab.com' probed 'app-prod.appspot.com' which someone else
    # owns and returns 200 - reported as the customer's asset.
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="not applicable for IP / internal hostname"
        return
    base_name = get_org_name(ctx.host) or ""
    if not base_name or base_name.lower() in _GENERIC_NAMES or len(base_name) < 4:
        ctx.state["skipped_reason"]=f"Brand name '{base_name}' too generic to probe App Engine namespaces without false-positive risk"
        return
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
