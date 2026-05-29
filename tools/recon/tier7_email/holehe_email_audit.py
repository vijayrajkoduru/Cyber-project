"""Holehe Email Audit v2 — VL-FORGE. Check if email is registered on 120+ sites."""
import asyncio, shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_HOLEHE=shutil.which("holehe")
async def gather(ctx):
    ctx.state["holehe_installed"]=bool(_HOLEHE)
    if not _HOLEHE: return
    # Common admin/info addresses to probe
    org=ctx.host.split(".")[0]
    emails=[f"admin@{ctx.host}",f"info@{ctx.host}",f"{org}@{ctx.host}",f"contact@{ctx.host}"]
    found=[]
    for em in emails[:2]:  # limit for speed
        try:
            proc=await asyncio.create_subprocess_exec(_HOLEHE,em,"--only-used","--no-color",
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            out,_=await asyncio.wait_for(proc.communicate(),timeout=120)
            for line in out.decode("utf-8",errors="ignore").splitlines():
                if "[+]" in line or "USED" in line.upper():
                    found.append({"email":em,"site":line.strip()[:200]})
            ctx.source(f"holehe-{em}")
        except: pass
    ctx.state["registrations_found"]=found[:30]
    ctx.state["registration_count"]=len(found)
def _r_no_holehe(s):
    if s.get("holehe_installed"): return None
    return {"name":"holehe binary not installed","severity":"INFO",
        "evidence":"pip install holehe — checks email registration across 120+ sites"}
def _r_registrations(s):
    n=s.get("registration_count",0)
    if n==0: return None
    sites=[(rr.get("site") or "") for rr in (s.get("registrations_found") or []) if rr.get("site")]
    _sample=", ".join(sites[:6])+(f" (+{len(sites)-6} more)" if len(sites)>6 else "")
    return {"name":f"Discovered email registered on {n} external site(s)","severity":"LOW","cwe":"T1589.002",
        "evidence":(f"Sites: {_sample}" if _sample else f"{n} site(s) matched"),
        "remediation":"Generic shared mailboxes (admin@, support@) widely reused expand the phishing / credential-stuffing surface; prefer per-service addresses."}
FINDING_RULES=[_r_no_holehe,_r_registrations]
INTEL_FIELDS=[("holehe installed","holehe_installed"),("Registrations","registration_count")]
@router.post("/api/recon/holehe_email_audit")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="holehe_email_audit",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["registrations_found","registration_count"])
def register(app): app.include_router(router)
