"""npm_package_audit — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    candidates = [base_name, f"{base_name}-api", f"@{base_name}/core"]
    found = []
    for name in candidates:
        try:
            def _q(n=name):
                with urllib.request.urlopen(f"https://registry.npmjs.org/{n}", timeout=6) as r: return json.loads(r.read())
            d = await asyncio.to_thread(_q)
            if d.get("name"):
                found.append({"name":d["name"],"latest":d.get("dist-tags",{}).get("latest"),"description":d.get("description","")[:120]})
        except Exception: pass
    ctx.state["npm_packages"] = found
    ctx.source("npm registry — name permutation")

RULES = [

]

@router.post("/api/recon/npm_package_audit")
async def recon_npm_package_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="npm_package_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("npm Packages","npm_packages")])

def register(app):
    app.include_router(router)
