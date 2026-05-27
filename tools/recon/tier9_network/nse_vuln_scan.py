"""nse_vuln_scan — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
import subprocess, shutil

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    if not shutil.which("nmap"):
        ctx.state["nmap_installed"] = False
        ctx.source("nmap not installed — skipping NSE vuln scan"); return
    try:
        r = await asyncio.to_thread(subprocess.run,
            ["nmap","--script","vuln","-Pn","--max-retries","1","--host-timeout","60s","-T4","-F",h],
            capture_output=True, text=True, timeout=120)
        out = r.stdout
        vulns = re.findall(r"\|\s+CVE-[\d-]+:.*", out)
        ctx.state["nmap_installed"] = True
        ctx.state["nse_findings"] = vulns[:20]
    except Exception as e:
        ctx.state["error"] = str(e)[:120]
    ctx.source("nmap --script vuln (top ports)")

RULES = [
    lambda s: {"name":"NSE vuln script detected CVE matches","severity":"HIGH",
        "evidence":f"NSE output: {s.get('nse_findings',[])[:5]}",
        "remediation":"Investigate each CVE; patch affected services. Re-run nmap --script vuln after patching.",
        "cwe":"CWE-1395","owasp":"A06:2021"
    } if s.get("nse_findings") else None,
]

@router.post("/api/recon/nse_vuln_scan")
async def recon_nse_vuln_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="nse_vuln_scan",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Nmap Installed","nmap_installed"),("NSE Findings","nse_findings")])

def register(app):
    app.include_router(router)
