"""ghunt_google_audit — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    if not shutil.which("ghunt"):
        ctx.state["ghunt_installed"] = False; ctx.source("ghunt not installed"); return
    ctx.state["ghunt_installed"] = True
    ctx.state["note"] = "GHunt requires authenticated Google session cookies stored locally. Run 'ghunt login' interactively."
    ctx.source("GHunt — Google account intel (cookie-gated)")

RULES = [

]

@router.post("/api/recon/ghunt_google_audit")
async def recon_ghunt_google_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="ghunt_google_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Ghunt Installed","ghunt_installed")])

def register(app):
    app.include_router(router)
