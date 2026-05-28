"""Sherlock Username v2 — VL-FORGE. Check username across 100+ social platforms."""
import asyncio, shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_SHERLOCK=shutil.which("sherlock")
async def gather(ctx):
    ctx.state["sherlock_installed"]=bool(_SHERLOCK)
    if not _SHERLOCK: return
    # Username candidates derived from domain
    org=ctx.host.split(".")[0]
    candidates=[org,f"{org}_official",f"{org}team",f"the{org}"]
    found_profiles=[]
    for u in candidates[:2]:  # limit for speed
        try:
            proc=await asyncio.create_subprocess_exec(_SHERLOCK,u,"--print-found","--timeout","8",
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            out,_=await asyncio.wait_for(proc.communicate(),timeout=60)
            for line in out.decode("utf-8",errors="ignore").splitlines():
                if "http" in line:
                    found_profiles.append({"username":u,"url":line.strip()})
            ctx.source(f"sherlock-{u}")
        except: pass
    ctx.state["found_profiles"]=found_profiles[:30]
    ctx.state["profile_count"]=len(found_profiles)
def _r_no_sherlock(s):
    if s.get("sherlock_installed"): return None
    return {"name":"sherlock binary not installed","severity":"INFO",
        "evidence":"pip install sherlock-project — username enum across 400+ sites"}
def _r_profiles(s):
    n=s.get("profile_count",0)
    if n==0: return None
    return {"name":f"{n} social profiles for brand-derived usernames","severity":"INFO","cwe":"T1593.001",
        "evidence":f"Sample: {(s.get('found_profiles') or [{}])[0].get('url','')[:80]}"}
FINDING_RULES=[_r_no_sherlock,_r_profiles]
INTEL_FIELDS=[("sherlock installed","sherlock_installed"),("Profiles","profile_count")]
@router.post("/api/recon/sherlock_username")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="sherlock_username",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found_profiles","profile_count"])
def register(app): app.include_router(router)
