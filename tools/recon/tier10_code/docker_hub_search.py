"""docker_hub_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    found = []
    try:
        url = f"https://hub.docker.com/v2/search/repositories/?query={base_name}&page_size=10"
        def _q():
            with urllib.request.urlopen(url, timeout=8) as r: return json.loads(r.read())
        d = await asyncio.to_thread(_q)
        for r in d.get("results",[])[:10]:
            found.append({"name":r.get("repo_name"),"stars":r.get("star_count"),"pulls":r.get("pull_count")})
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.state["docker_repos"] = found
    ctx.source("Docker Hub public search")

RULES = [

]

@router.post("/api/recon/docker_hub_search")
async def recon_docker_hub_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="docker_hub_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Docker Repos","docker_repos")])

def register(app):
    app.include_router(router)
