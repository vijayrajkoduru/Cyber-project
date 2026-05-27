"""reddit_search — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    code, d = await get_json(f"https://www.reddit.com/search.json?q={urllib.parse.quote(name)}&limit=15&sort=new",
                             headers={"User-Agent":"VulnusLab/1.0 OSINT scanner"})
    posts = ((d or {}).get("data") or {}).get("children",[])
    ctx.state["post_count"] = len(posts)
    ctx.state["posts"] = [{"title":p.get("data") or {}.get("title","")[:120],"subreddit":p.get("data") or {}.get("subreddit")} for p in posts[:10]]
    ctx.source("Reddit JSON search")

RULES = [

]

@router.post("/api/recon/reddit_search")
async def recon_reddit_search(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="reddit_search",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Post Count","post_count"),("Posts","posts")])

def register(app):
    app.include_router(router)
