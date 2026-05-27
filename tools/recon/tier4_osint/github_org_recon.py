"""github_org_recon — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    token = os.environ.get("GITHUB_TOKEN","")
    hd = {"Accept":"application/vnd.github.v3+json"}
    if token: hd["Authorization"] = f"token {token}"
    code, d = await get_json(f"https://api.github.com/orgs/{name}", headers=hd)
    if code == 200 and isinstance(d, dict) and d.get("login"):
        ctx.state["org_found"] = True
        ctx.state["org"] = {"login":d.get("login"),"public_repos":d.get("public_repos"),"created_at":d.get("created_at"),"description":d.get("description")}
        code2, r = await get_json(f"https://api.github.com/orgs/{name}/repos?per_page=10", headers=hd)
        ctx.state["recent_repos"] = [{"name":x.get("name"),"language":x.get("language")} for x in (r or [])[:10]] if isinstance(r,list) else []
    else:
        ctx.state["org_found"] = False
    ctx.source("GitHub /orgs/ + /orgs/{name}/repos")

RULES = [

]

@router.post("/api/recon/github_org_recon")
async def recon_github_org_recon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="github_org_recon",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Org Found","org_found"),("Org","org"),("Recent Repos","recent_repos")])

def register(app):
    app.include_router(router)
