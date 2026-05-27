"""gitlab_bitbucket_scan — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, urllib.parse, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    hits = []
    try:
        url = f"https://gitlab.com/api/v4/search?scope=blobs&search={urllib.parse.quote(h)}"
        def _s():
            with urllib.request.urlopen(url, timeout=8) as r: return json.loads(r.read())
        d = await asyncio.to_thread(_s)
        if isinstance(d, list):
            for it in d[:5]: hits.append({"project_id":it.get("project_id"),"path":it.get("path")})
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["gitlab_hits"] = hits
    ctx.source("GitLab public code search")

RULES = [

]

@router.post("/api/recon/gitlab_bitbucket_scan")
async def recon_gitlab_bitbucket_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gitlab_bitbucket_scan",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Gitlab Hits","gitlab_hits")])

def register(app):
    app.include_router(router)
