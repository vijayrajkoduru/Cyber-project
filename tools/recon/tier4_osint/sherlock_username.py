"""sherlock_username — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    if not shutil.which("sherlock"):
        ctx.state["sherlock_installed"] = False
        ctx.source("sherlock binary not installed"); return
    try:
        r = await asyncio.to_thread(subprocess.run, ["sherlock","--timeout","5","--print-found",name],
                                    capture_output=True, text=True, timeout=120)
        hits = [ln.split()[-1] for ln in r.stdout.splitlines() if "http" in ln][:15]
        ctx.state["sherlock_installed"] = True
        ctx.state["profiles_found"] = hits
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.source("sherlock username scan across 400+ sites")

RULES = [

]

@router.post("/api/recon/sherlock_username")
async def recon_sherlock_username(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="sherlock_username",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Sherlock Installed","sherlock_installed"),("Profiles Found","profiles_found")])

def register(app):
    app.include_router(router)
