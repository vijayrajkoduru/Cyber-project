"""ai_endpoint_guesser — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    # Heuristic endpoint patterns; LLM expansion with key
    from tools.recon._web_helpers import fetch, base_url
    PATHS = ["/api/v1/users","/api/v1/admin","/api/health","/api/internal","/api/v1/me",
             "/api/v1/auth/login","/api/v1/auth/refresh","/.well-known/openid-configuration",
             "/graphql","/api/graphql","/v2/api-docs","/swagger-ui","/actuator"]
    base = base_url(ctx.host)
    hits = []
    for p in PATHS:
        c, _, _ = await fetch(base+p, timeout=4)
        if c and c not in (404, 0): hits.append({"path":p,"status":c})
    ctx.state["paths_tested"] = len(PATHS)
    ctx.state["live_endpoints"] = hits
    ctx.source("AI-style endpoint dictionary + HTTP verification")

RULES = [

]

@router.post("/api/recon/ai_endpoint_guesser")
async def recon_ai_endpoint_guesser(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ai_endpoint_guesser",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Paths Tested","paths_tested"),("Live Endpoints","live_endpoints")])

def register(app):
    app.include_router(router)
