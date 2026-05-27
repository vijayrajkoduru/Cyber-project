"""securitytrails_subdomains — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    key = os.environ.get("SECURITYTRAILS_API_KEY","")
    if not key:
        ctx.state["api_key_configured"] = False
        ctx.source("SECURITYTRAILS_API_KEY not set"); return
    found = set()
    try:
        def _fetch():
            req = urllib.request.Request(f"https://api.securitytrails.com/v1/domain/{h}/subdomains",
                headers={"APIKEY": key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=12) as r:
                return json.loads(r.read())
        d = await asyncio.to_thread(_fetch)
        for s in d.get("subdomains", []):
            found.add(f"{s}.{h}")
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    verified = await bulk_check(list(found), concurrency=20)
    ctx.state["api_key_configured"] = True
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source("SecurityTrails API + DNS verification")

RULES = [

]

@router.post("/api/recon/securitytrails_subdomains")
async def recon_securitytrails_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="securitytrails_subdomains",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
