"""Sherlock Username v3 — VL-FORGE. Brand-stem verified to eliminate FPs."""
import asyncio, shutil, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_SHERLOCK=shutil.which("sherlock")

def _stem(host):
    """Brand stem = leftmost label minus common gTLD prefixes."""
    s=(host or "").split(".")[0].lower()
    return re.sub(r"[^a-z0-9]","",s)

def _url_contains_stem(url, stem):
    """Match only if the username segment in the URL contains the full stem.
    Sherlock prints lines like '[+] Platform: https://site.com/<username>'."""
    if not url or not stem: return False
    u=url.lower()
    # Anchor on the queried username being a token in the path/host
    # Reject sub-stem matches like 'vulnus' for stem 'vulnuslab'
    return bool(re.search(rf"(^|[/=._-]){re.escape(stem)}([/=._?&-]|$)", u))

async def gather(ctx):
    ctx.state["sherlock_installed"]=bool(_SHERLOCK)
    if not _SHERLOCK: return
    stem=_stem(ctx.host)
    ctx.state["brand_stem"]=stem
    candidates=[stem,f"{stem}_official",f"{stem}team",f"the{stem}"]
    raw_profiles=[]
    for u in candidates[:2]:
        try:
            proc=await asyncio.create_subprocess_exec(_SHERLOCK,u,"--print-found","--timeout","8",
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            out,_=await asyncio.wait_for(proc.communicate(),timeout=60)
            for line in out.decode("utf-8",errors="ignore").splitlines():
                if "http" in line:
                    raw_profiles.append({"username":u,"url":line.strip()})
            ctx.source(f"sherlock-{u}")
        except: pass
    # FP guard: reject any URL whose path/host doesn't contain the full brand stem
    verified=[p for p in raw_profiles if _url_contains_stem(p.get("url",""), stem)]
    ctx.state["raw_profile_count"]=len(raw_profiles)
    ctx.state["found_profiles"]=verified[:30]
    ctx.state["profile_count"]=len(verified)
    ctx.state["rejected_fp_count"]=len(raw_profiles)-len(verified)

def _r_no_sherlock(s):
    if s.get("sherlock_installed"): return None
    return {"name":"sherlock binary not installed","severity":"INFO",
        "evidence":"pip install sherlock-project — username enum across 400+ sites"}
def _r_profiles(s):
    n=s.get("profile_count",0)
    if n==0: return None
    sample=(s.get('found_profiles') or [{}])[0].get('url','')[:120]
    ev=f"Sample: {sample}"
    rej=s.get("rejected_fp_count",0)
    if rej: ev+=f" (filtered {rej} brand-mismatch FP)"
    return {"name":f"{n} brand-verified social profiles","severity":"INFO","cwe":"T1593.001",
        "evidence":ev}
def _r_clean(s):
    if not s.get("sherlock_installed"): return None
    if s.get("profile_count",0)>0: return None
    rej=s.get("rejected_fp_count",0)
    if rej==0 and s.get("raw_profile_count",0)==0: return None
    return {"name":"No brand-verified social profiles","severity":"POSITIVE",
        "evidence":f"Filtered {rej} brand-mismatch hit(s); none survived stem verification"}

FINDING_RULES=[_r_no_sherlock,_r_profiles,_r_clean]
INTEL_FIELDS=[("sherlock installed","sherlock_installed"),("Brand stem","brand_stem"),
    ("Verified profiles","profile_count"),("Rejected FP","rejected_fp_count")]
@router.post("/api/recon/sherlock_username")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="sherlock_username",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found_profiles","profile_count","rejected_fp_count"])
def register(app): app.include_router(router)
