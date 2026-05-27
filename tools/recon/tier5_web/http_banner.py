"""http_banner — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, _ = await fetch(url)
    ctx.state["status"] = code
    ctx.state["server"] = hdrs.get("Server","") or hdrs.get("server","")
    ctx.state["powered_by"] = hdrs.get("X-Powered-By","") or hdrs.get("x-powered-by","")
    ctx.state["via"] = hdrs.get("Via","")
    ctx.source("HTTP banner probe")

RULES = [
    lambda s: {"name":"Server software version disclosed","severity":"LOW",
        "evidence":f"Server header: {s['server']}",
        "remediation":"Strip Server/X-Powered-By headers via reverse proxy (server_tokens off in nginx)",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if any(c.isdigit() for c in s.get("server","")) else None,
    lambda s: {"name":"X-Powered-By header leaks framework","severity":"LOW",
        "evidence":f"X-Powered-By: {s['powered_by']}",
        "remediation":"Remove X-Powered-By header — exposes framework version to attackers",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if s.get("powered_by") else None,
]

@router.post("/api/recon/http_banner")
async def recon_http_banner(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="http_banner",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Status","status"),("Server","server"),("Powered By","powered_by"),("Via","via")])

def register(app):
    app.include_router(router)
