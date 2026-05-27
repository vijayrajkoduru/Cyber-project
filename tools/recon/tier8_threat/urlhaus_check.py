"""urlhaus_check — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import urllib.request, urllib.parse, json

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    try:
        def _post():
            data = urllib.parse.urlencode({"host":h}).encode()
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/host/", data=data)
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read())
        d = await asyncio.to_thread(_post)
        hits = d.get("urls",[]) if d.get("query_status")=="ok" else []
    except Exception as e:
        hits = []; ctx.state["error"] = str(e)[:120]
    ctx.state["malware_urls"] = hits[:10]
    ctx.state["hit_count"] = len(hits)
    ctx.source("URLhaus public API (abuse.ch)")

RULES = [
    lambda s: {"name":"Target hosts malware (URLhaus listing)","severity":"CRITICAL",
        "evidence":f"Malicious URLs: {s.get('malware_urls')}",
        "remediation":"Investigate compromise — clean infected paths. Submit removal request after cleanup.",
        "cwe":"N/A","owasp":"N/A"
    } if s.get("hit_count",0) > 0 else None,
]

@router.post("/api/recon/urlhaus_check")
async def recon_urlhaus_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="urlhaus_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Malware Urls","malware_urls"),("Hit Count","hit_count")])

def register(app):
    app.include_router(router)
