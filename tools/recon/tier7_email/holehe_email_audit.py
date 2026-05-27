"""holehe_email_audit — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    if not shutil.which("holehe"):
        ctx.state["holehe_installed"] = False; ctx.source("holehe not installed"); return
    # Test the most likely admin email
    email = f"admin@{ctx.host}"
    try:
        r = await asyncio.to_thread(subprocess.run, ["holehe","--no-color","--only-used",email],
                                    capture_output=True, text=True, timeout=120)
        used = [ln.strip("[+] ").strip() for ln in r.stdout.splitlines() if "[+]" in ln][:30]
        ctx.state["holehe_installed"] = True
        ctx.state["email_tested"] = email
        ctx.state["services_registered"] = used
        ctx.state["count"] = len(used)
    except Exception as e: ctx.state["error"] = str(e)[:120]
    ctx.source("holehe — forgot-password enumeration (120+ services)")

RULES = [

]

@router.post("/api/recon/holehe_email_audit")
async def recon_holehe_email_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="holehe_email_audit",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Holehe Installed","holehe_installed"),("Services Registered","services_registered"),("Count","count")])

def register(app):
    app.include_router(router)
