"""amass_passive — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    if not shutil.which("amass"):
        ctx.state["amass_installed"] = False
        ctx.source("amass binary not found"); return
    found = set()
    try:
        r = await asyncio.to_thread(subprocess.run,
            ["amass","enum","-passive","-d",h,"-timeout","2","-silent"],
            capture_output=True, text=True, timeout=180)
        for ln in r.stdout.splitlines():
            s = ln.strip().lower()
            if s.endswith("."+h) or s == h: found.add(s)
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    verified = await bulk_check(list(found), concurrency=25)
    ctx.state["amass_installed"] = True
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source("amass enum -passive + DNS verification")

RULES = [

]

@router.post("/api/recon/amass_passive")
async def recon_amass_passive(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="amass_passive",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Amass Installed","amass_installed"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
