"""pypi_package_audit — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request, json

router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    candidates = [base_name, f"{base_name}-sdk", f"{base_name}-client", f"py-{base_name}"]
    found = []
    for name in candidates:
        try:
            def _q(n=name):
                with urllib.request.urlopen(f"https://pypi.org/pypi/{n}/json", timeout=6) as r: return json.loads(r.read())
            d = await asyncio.to_thread(_q)
            info = d.get("info",{})
            if info.get("name"):
                found.append({"name":info["name"],"version":info.get("version"),"author":info.get("author","")[:80]})
        except Exception: pass
    ctx.state["pypi_packages"] = found
    ctx.source("PyPI registry — name permutation")

RULES = [

]

@router.post("/api/recon/pypi_package_audit")
async def recon_pypi_package_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="pypi_package_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("PyPI Packages","pypi_packages")])

def register(app):
    app.include_router(router)
