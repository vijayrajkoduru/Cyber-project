"""js_endpoint_extract — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url, set_auth_from_req
import urllib.parse

router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    _, _, body = await fetch(base)
    text = body.decode("utf-8","ignore")
    js_urls = list(set(re.findall(r'(?i)src=[\"\']([^\"\']+\.js[^\"\']*)', text)))[:8]
    found = set()
    for j in js_urls:
        full = urllib.parse.urljoin(base, j)
        _, _, jb = await fetch(full, timeout=6)
        jt = jb.decode("utf-8","ignore")
        for m in re.finditer(r'[\"\']/(api|v\d+|graphql|admin|auth|rest|rpc)/[a-z0-9/_.-]+[\"\']', jt, re.I):
            found.add(m.group(0).strip('\'"\''))
    ctx.state["js_files"] = js_urls
    ctx.state["api_endpoints"] = sorted(found)[:60]
    ctx.state["count"] = len(found)
    ctx.source("JS file harvest + API path regex")

RULES = [

]

@router.post("/api/recon/js_endpoint_extract")
async def recon_js_endpoint_extract(req: ScanRequest, _=Depends(verify_scan_quota)):
    set_auth_from_req(req)
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="js_endpoint_extract",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Js Files","js_files"),("API Endpoints","api_endpoints"),("Count","count")])

def register(app):
    app.include_router(router)
