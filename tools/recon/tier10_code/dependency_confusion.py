"""Dependency Confusion v2 — VL-FORGE."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _npm(n):
    try: return requests.get(f"https://registry.npmjs.org/{n}",timeout=6).status_code==200
    except Exception: return None
def _pypi(n):
    try: return requests.get(f"https://pypi.org/pypi/{n}/json",timeout=6).status_code==200
    except Exception: return None
async def gather(ctx):
    org=ctx.host.split(".")[0]
    cands=[f"{org}-internal",f"{org}-shared",f"{org}-utils",f"{org}-common",f"{org}-core",
        f"@{org}/internal",f"@{org}/shared",f"{org}-private",f"{org}-tools",f"internal-{org}"]
    npm_res=await asyncio.gather(*[asyncio.to_thread(_npm,c) for c in cands])
    pypi_res=await asyncio.gather(*[asyncio.to_thread(_pypi,c) for c in cands if "@" not in c])
    unc_npm=[c for c,r in zip(cands,npm_res) if r is False]
    unc_pypi=[c for c,r in zip([x for x in cands if "@" not in x],pypi_res) if r is False]
    ctx.source(f"checked-{len(cands)*2}")
    ctx.state.update({"unclaimed_npm":unc_npm,"unclaimed_pypi":unc_pypi,
        "unclaimed_count":len(unc_npm)+len(unc_pypi)})
def _r_vuln(s):
    n=s.get("unclaimed_count",0)
    if n==0: return None
    return {"name":f"Namespace hardening: {n} internal-looking package names unclaimed on npm/pypi - pre-register to prevent future dependency confusion",
        "severity":"INFO","cwe":"CWE-829","owasp":"A06:2021",
        "evidence":f"npm: {s.get('unclaimed_npm')} | pypi: {s.get('unclaimed_pypi')}",
        "remediation":"Pre-register these names on npm OR configure .npmrc with scope-private registry"}
def _r_safe(s):
    if s.get("unclaimed_count",0)>0: return None
    return {"name":"No dependency confusion exposure","severity":"POSITIVE",
        "evidence":"All internal-looking names already claimed"}
FINDING_RULES=[_r_vuln,_r_safe]
INTEL_FIELDS=[("Unclaimed npm","unclaimed_npm"),("Unclaimed pypi","unclaimed_pypi"),("Total","unclaimed_count")]
@router.post("/api/recon/dependency_confusion")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="dependency_confusion",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["unclaimed_npm","unclaimed_pypi","unclaimed_count"])
def register(app): app.include_router(router)
