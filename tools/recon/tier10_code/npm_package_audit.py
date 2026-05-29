"""npm_package_audit — VL-FORGE. Own-code (npm registry search, no key): org packages."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _search(term):
    try:
        r=requests.get("https://registry.npmjs.org/-/v1/search",
            params={"text":term,"size":20}, timeout=8, headers={"User-Agent":"VulnusLab/1.0"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    org=str(ctx.host).split(".")[0]
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("npm")
    pk=[{"name":o["package"]["name"]} for o in (j.get("objects") or [])
        if org.lower() in str(o.get("package",{}).get("name","")).lower()]
    ctx.state.update({"org":org,"packages":pk,"pkg_count":len(pk)})
def _r_found(s):
    p=s.get("packages") or []
    if not p: return None
    return {"name":"%d npm package(s) match the org"%len(p),"severity":"INFO","cwe":"CWE-1104",
        "evidence":", ".join(x["name"] for x in p[:6]),
        "remediation":"Confirm ownership; unowned look-alikes enable dependency-confusion. Pin/scope internal packages."}
def _r_clean(s):
    if not s.get("reachable") or s.get("packages"): return None
    return {"name":"No org-matched npm packages","severity":"POSITIVE","evidence":"npm registry search: none for '%s'"%s.get("org","")}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Org term","org"),("Packages found","pkg_count"),("Packages","packages")]
@router.post("/api/recon/npm_package_audit")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="npm_package_audit",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,flat_field_keys=["packages"])
def register(app): app.include_router(router)
