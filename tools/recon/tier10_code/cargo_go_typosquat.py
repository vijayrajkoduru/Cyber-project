"""cargo_go_typosquat — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import urllib.request

router = APIRouter()

async def gather(ctx: ScanContext):
    base_name = ctx.host.split(".")[0]
    typos = [base_name+"s", base_name+"-rs", base_name+"_rs", base_name+"go", "go-"+base_name]
    cargo_taken = []
    for n in typos:
        try:
            req = urllib.request.Request(f"https://crates.io/api/v1/crates/{n}", method="HEAD")
            def _q(r=req):
                try:
                    with urllib.request.urlopen(r, timeout=4) as resp: return resp.status
                except urllib.error.HTTPError as e: return e.code
                except Exception: return 0
            if await asyncio.to_thread(_q) == 200: cargo_taken.append(n)
        except Exception: pass
    ctx.state["cargo_typos_taken"] = cargo_taken
    ctx.source("Cargo crates.io typosquat probe")

RULES = [

]

@router.post("/api/recon/cargo_go_typosquat")
async def recon_cargo_go_typosquat(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cargo_go_typosquat",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Cargo Typos Taken","cargo_typos_taken")])

def register(app):
    app.include_router(router)
