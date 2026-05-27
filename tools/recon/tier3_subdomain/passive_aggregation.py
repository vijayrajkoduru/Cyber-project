"""passive_aggregation — VL-FORGE Recon §3 Subdomain Enumeration (real, zero-FP)."""
import asyncio, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._subdomain_helpers import resolves, bulk_check
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    sources = []
    found = set()
    for tool, args in [("subfinder",["subfinder","-d",h,"-silent","-timeout","8","-max-time","20"]),
                       ("findomain",["findomain","-t",h,"--quiet"])]:
        if not shutil.which(tool): continue
        try:
            r = await asyncio.to_thread(subprocess.run, args, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    s = ln.strip().lower()
                    if s.endswith("."+h) or s == h:
                        found.add(s)
                sources.append(tool)
        except Exception: pass
    # Verify discovered ones resolve (zero-FP)
    verified = await bulk_check(list(found), concurrency=20)
    ctx.state["sources_used"] = sources
    ctx.state["raw_count"] = len(found)
    ctx.state["discovered"] = verified
    ctx.state["count"] = len(verified)
    ctx.source(f"Passive aggregation via {sources or 'none — subfinder/findomain not installed'}")

RULES = [

]

@router.post("/api/recon/passive_aggregation")
async def recon_passive_aggregation(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="passive_aggregation",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Sources Used","sources_used"),("Discovered","discovered"),("Count","count")])

def register(app):
    app.include_router(router)
