"""azure_app_services — VL-FORGE Recon (real, zero-FP)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch


router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    candidates = [f"{base_name}.azurewebsites.net", f"{base_name}-prod.azurewebsites.net", f"{base_name}-staging.azurewebsites.net"]
    found = []
    for hn in candidates:
        c, _, _ = await fetch(f"https://{hn}/", timeout=4)
        if c and c != 404: found.append({"hostname":hn,"status":c})
    ctx.state["discovered"] = found
    ctx.source("Azure App Service hostname permutation")

RULES = [

]

@router.post("/api/recon/azure_app_services")
async def recon_azure_app_services(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="azure_app_services",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
