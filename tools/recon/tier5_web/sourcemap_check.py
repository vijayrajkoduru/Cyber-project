"""sourcemap_check — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import urllib.parse

router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    _, _, body = await fetch(base)
    text = body.decode("utf-8","ignore")
    js_files = re.findall(r'(?i)src=[\"\']([^\"\']+\.js[^\"\']*)', text)[:5]
    exposed_maps = []
    for j in js_files:
        full = urllib.parse.urljoin(base, j) + ".map"
        c, _, b = await fetch(full, timeout=5)
        if c == 200 and (b.startswith(b"{") or b'"sources"' in b):
            exposed_maps.append({"map_url": full, "size_bytes": len(b)})
    ctx.state["maps_exposed"] = exposed_maps
    ctx.state["count"] = len(exposed_maps)
    ctx.source("JS .map file probe")

RULES = [
    lambda s: {"name":"JavaScript source maps publicly accessible","severity":"MEDIUM",
        "evidence":f"{s.get('count')} .map files exposed — reveals original (pre-minified) source code including comments, vars",
        "remediation":"Remove .map files from production OR restrict to /_internal path with auth",
        "cwe":"CWE-540","owasp":"A05:2021"
    } if s.get("count",0) > 0 else None,
]

@router.post("/api/recon/sourcemap_check")
async def recon_sourcemap_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="sourcemap_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Maps Exposed","maps_exposed"),("Count","count")])

def register(app):
    app.include_router(router)
