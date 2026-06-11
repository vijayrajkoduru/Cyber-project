"""Amass Passive v2 — VL-FORGE. amass binary if available, fallback to API merge."""
import asyncio, shutil, requests, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_AMASS=shutil.which("amass")
async def _amass_cli(host):
    if not _AMASS: return []
    try:
        proc=await asyncio.create_subprocess_exec(_AMASS,"enum","-passive","-d",host,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        out,_=await asyncio.wait_for(proc.communicate(),timeout=60)
        return [l.strip().lower() for l in out.decode("utf-8",errors="ignore").splitlines() if host in l]
    except: return []
def _g(u):
    try:
        r=requests.get(u,timeout=15,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    h=ctx.host; subs=set(); used_amass=False
    if _AMASS:
        ctx.source("amass-cli")
        for s in await _amass_cli(h): subs.add(s)
        used_amass=True
    else:
        # Fallback: merge multiple free sources
        crt=await asyncio.to_thread(_g,f"https://crt.sh/?q=%25.{h}&output=json")
        if crt:
            ctx.source("crt.sh-fallback")
            try:
                for e in json.loads(crt)[:200]:
                    for n in (e.get("name_value","") or "").split("\n"):
                        n=n.strip().lower()
                        if n.endswith(h) and "*" not in n and n!=h: subs.add(n)
            except: pass
    ctx.state.update({"amass_binary_available":bool(_AMASS),"used_amass":used_amass,
        "subdomains":sorted(subs)[:100],"count":len(subs)})
def _r_no_amass(s):
    if s.get("amass_binary_available"): return None
    return {"name":"amass binary not installed","severity":"INFO",
        "evidence":"Falling back to crt.sh. Install amass for deeper passive enum.",
        "remediation":"go install -v github.com/owasp-amass/amass/v4/...@master"}
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains via {'amass' if s.get('used_amass') else 'fallback'}","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5])}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains from passive enum","severity":"POSITIVE","evidence":"All sources empty"}
FINDING_RULES=[_r_no_amass,_r_found,_r_clean]
INTEL_FIELDS=[("amass installed","amass_binary_available"),("Subdomains","count")]
@router.post("/api/recon/amass_passive")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="amass_passive",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
