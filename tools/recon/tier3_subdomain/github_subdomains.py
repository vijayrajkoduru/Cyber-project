"""github_subdomains — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import urllib.request, urllib.parse, json, re

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    token = os.environ.get("GITHUB_TOKEN","")
    if not token:
        ctx.state["api_key_configured"] = False
        ctx.source("GITHUB_TOKEN not set"); return
    found = set()
    try:
        q = urllib.parse.quote(f'"{h}"')
        def _search():
            req = urllib.request.Request(
                f"https://api.github.com/search/code?q={q}&per_page=30",
                headers={"Authorization": f"token {token}","Accept":"application/vnd.github.v3+json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        d = await asyncio.to_thread(_search)
        for item in d.get("items",[])[:30]:
            url = item.get("html_url","")
            # Fetch raw content
            raw = url.replace("github.com","raw.githubusercontent.com").replace("/blob/","/")
            try:
                def _raw():
                    req2 = urllib.request.Request(raw, headers={"Authorization":f"token {token}"})
                    with urllib.request.urlopen(req2, timeout=6) as r2:
                        return r2.read(20000).decode("utf-8","ignore")
                body = await asyncio.to_thread(_raw)
                for m in re.finditer(rf"([a-z0-9][a-z0-9-]*\.{re.escape(h)})", body):
                    found.add(m.group(1).lower())
            except Exception: pass
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    verified = await bulk_check(list(found), concurrency=20)
    ctx.state["api_key_configured"] = True
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source("GitHub code search + DNS verification")

RULES = [

]

@router.post("/api/recon/github_subdomains")
async def recon_github_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="github_subdomains",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("API Key Configured","api_key_configured"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
