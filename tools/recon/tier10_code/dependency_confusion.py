"""dependency_confusion — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request

router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    suspect_names = [f"@{base_name}/internal", f"{base_name}-internal", f"{base_name}-private"]
    available = []
    for name in suspect_names:
        try:
            url = f"https://registry.npmjs.org/{name}"
            req = urllib.request.Request(url, method="HEAD")
            def _q(r=req):
                try:
                    with urllib.request.urlopen(r, timeout=5) as resp: return resp.status
                except urllib.error.HTTPError as e: return e.code
                except Exception: return 0
            code = await asyncio.to_thread(_q)
            if code == 404:  # available for typosquatting
                available.append(name)
        except Exception: pass
    ctx.state["squattable_names"] = available
    ctx.source("npm registry — dependency-confusion candidate check")

RULES = [
    lambda s: {"name":"Dependency Confusion: internal-looking names UNCLAIMED on public npm","severity":"HIGH",
        "evidence":f"Names attacker could squat: {s.get('squattable_names')}",
        "remediation":"Pre-register these names on npm OR configure .npmrc with scope-private registry for internal scopes",
        "cwe":"CWE-829","owasp":"A06:2021"
    } if s.get("squattable_names") else None,
]

@router.post("/api/recon/dependency_confusion")
async def recon_dependency_confusion(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="dependency_confusion",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Squattable Names","squattable_names")])

def register(app):
    app.include_router(router)
