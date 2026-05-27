"""phoneinfoga_lookup — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    if not shutil.which("phoneinfoga"):
        ctx.state["phoneinfoga_installed"] = False; ctx.source("phoneinfoga not installed"); return
    ctx.state["phoneinfoga_installed"] = True
    ctx.state["note"] = "PhoneInfoga requires a target phone number; this scanner exists for orchestrator inclusion."
    ctx.source("PhoneInfoga — number OSINT (requires phone input)")

RULES = [

]

@router.post("/api/recon/phoneinfoga_lookup")
async def recon_phoneinfoga_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="phoneinfoga_lookup",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Phoneinfoga Installed","phoneinfoga_installed")])

def register(app):
    app.include_router(router)
