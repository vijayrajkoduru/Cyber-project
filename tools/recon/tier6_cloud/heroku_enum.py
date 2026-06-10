"""heroku_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

_HEROKU_SUFFIXES = ["", "-prod", "-app", "-api", "-staging", "-dev", "-test",
                    "-www", "-web", "-portal", "-admin", "-internal"]


async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    candidates = [f"{base_name}{sfx}.herokuapp.com" for sfx in _HEROKU_SUFFIXES]
    async def _probe(hn):
        c, _, _ = await fetch(f"https://{hn}/", timeout=4)
        return {"hostname": hn, "status": c} if c and c != 404 else None
    results = await asyncio.gather(*(_probe(h) for h in candidates))
    ctx.state["discovered"] = [r for r in results if r]
    ctx.source("Heroku app hostname permutation")

RULES = [

]

@router.post("/api/recon/heroku_enum")
async def recon_heroku_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="heroku_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered","discovered")])

def register(app):
    app.include_router(router)
