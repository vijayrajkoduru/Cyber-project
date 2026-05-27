"""robots_sitemap — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    rc, _, rb = await fetch(f"{base}/robots.txt")
    sc, _, sb = await fetch(f"{base}/sitemap.xml")
    robots_text = rb.decode("utf-8","ignore") if rc == 200 else ""
    sitemap_text = sb.decode("utf-8","ignore") if sc == 200 else ""
    disallowed = re.findall(r"(?i)^Disallow:\s*(\S+)", robots_text, re.M)
    sitemap_urls = re.findall(r"<loc>(.*?)</loc>", sitemap_text)
    sensitive = [d for d in disallowed if any(k in d.lower() for k in ("admin","backup","private","internal","secret","config","api/private"))]
    ctx.state["robots_status"] = rc
    ctx.state["sitemap_status"] = sc
    ctx.state["disallowed"] = disallowed[:50]
    ctx.state["sitemap_urls"] = sitemap_urls[:50]
    ctx.state["sensitive_disallowed"] = sensitive
    ctx.source("/robots.txt and /sitemap.xml fetch + parse")

RULES = [
    lambda s: {"name":"robots.txt discloses sensitive paths","severity":"LOW",
        "evidence":f"robots.txt Disallow lists sensitive paths: {s.get('sensitive_disallowed')}",
        "remediation":"Don't rely on robots.txt for access control — it advertises what you want to hide. Apply real auth/ACL instead.",
        "cwe":"CWE-200","owasp":"A01:2021"
    } if s.get("sensitive_disallowed") else None,
]

@router.post("/api/recon/robots_sitemap")
async def recon_robots_sitemap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="robots_sitemap",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Robots Status","robots_status"),("Sitemap Status","sitemap_status"),("Disallowed","disallowed"),("Sitemap Urls","sitemap_urls")])

def register(app):
    app.include_router(router)
