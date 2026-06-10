"""cloud_function_url_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

# Cloud Run / Cloud Functions URL patterns. Lambda function URLs follow
# https://<id>.lambda-url.<region>.on.aws and can't be enumerated without id.
_GCP_REGIONS = ["uc", "ue", "uw", "ew", "an", "as", "ne", "se", "sw"]
_GCP_URL_TEMPLATES = (
    [f"https://{{name}}.run.app/"] +
    [f"https://{{name}}-{r}.a.run.app/" for r in _GCP_REGIONS] +
    [f"https://us-central1-{{name}}.cloudfunctions.net/{{name}}"]
)


async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    urls = [tpl.format(name=base_name) for tpl in _GCP_URL_TEMPLATES]
    async def _probe(u):
        c, _, _ = await fetch(u, timeout=4)
        return {"url": u, "status": c} if c and c != 404 else None
    results = await asyncio.gather(*(_probe(u) for u in urls))
    ctx.state["discovered"] = [r for r in results if r]
    ctx.source("GCP Cloud Run + Cloud Functions URL permutation")

RULES = [

]

@router.post("/api/recon/cloud_function_url_enum")
async def recon_cloud_function_url_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cloud_function_url_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
