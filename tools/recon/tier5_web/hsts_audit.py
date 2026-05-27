"""hsts_audit — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, _ = await fetch(url)
    hsts = hdrs.get("Strict-Transport-Security","") or hdrs.get("strict-transport-security","")
    ctx.state["hsts_header"] = hsts
    max_age = 0
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m: max_age = int(m.group(1))
    ctx.state["max_age"] = max_age
    ctx.state["includes_subdomains"] = "includeSubDomains" in hsts.lower()
    ctx.state["preload"] = "preload" in hsts.lower()
    ctx.source("HSTS header analysis")

RULES = [
    lambda s: {"name":"HSTS max-age is too short","severity":"LOW",
        "evidence":f"max-age={s.get('max_age')} — recommended is 31536000 (1 year)",
        "remediation":"Set HSTS max-age to at least 31536000 seconds",
        "cwe":"CWE-319","owasp":"A02:2021"
    } if s.get("hsts_header") and 0 < s.get("max_age",0) < 31536000 else None,
]

@router.post("/api/recon/hsts_audit")
async def recon_hsts_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="hsts_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("HSTS Header","hsts_header"),("Max Age","max_age"),("Includes Subdomains","includes_subdomains"),("Preload","preload")])

def register(app):
    app.include_router(router)
