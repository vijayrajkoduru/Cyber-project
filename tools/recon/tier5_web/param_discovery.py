"""param_discovery — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    _, _, body = await fetch(base)
    text = body.decode("utf-8","ignore")
    form_params = set()
    for m in re.finditer(r'<input[^>]+name=[\"\']([^\"\']+)', text, re.I):
        form_params.add(m.group(1))
    js_params = set(re.findall(r'[\"\']([a-z][a-zA-Z0-9_]{2,30})[\"\']\s*:', text))
    ctx.state["form_params"] = sorted(form_params)[:40]
    ctx.state["js_params"] = sorted(js_params)[:40]
    ctx.source("HTML form + JS literal extraction")

RULES = [

]

@router.post("/api/recon/param_discovery")
async def recon_param_discovery(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="param_discovery",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Form Params","form_params"),("Js Params","js_params")])

def register(app):
    app.include_router(router)
