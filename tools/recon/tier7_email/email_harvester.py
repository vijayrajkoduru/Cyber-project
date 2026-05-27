"""email_harvester — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    from tools.recon._web_helpers import fetch, base_url
    emails = set()
    for path in ("/","/contact","/about","/team","/support","/imprint","/legal"):
        c, _, b = await fetch(base_url(h)+path, timeout=5)
        if c == 200:
            for m in re.finditer(rb"[a-zA-Z0-9._%+-]+@" + re.escape(h.encode()), b):
                emails.add(m.group().decode("utf-8","ignore").lower())
    ctx.state["emails_found"] = sorted(emails)[:30]
    ctx.state["count"] = len(emails)
    ctx.source("Site crawl — common pages + email regex (domain-scoped)")

RULES = [

]

@router.post("/api/recon/email_harvester")
async def recon_email_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="email_harvester",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Emails Found","emails_found"),("Count","count")])

def register(app):
    app.include_router(router)
