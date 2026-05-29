"""cargo_go_typosquat — VL-FORGE. Own-code (crates.io API, no key): org Rust crates + typosquat surface."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _search(term):
    try:
        r=requests.get("https://crates.io/api/v1/crates",
            params={"q":term,"per_page":20}, timeout=8, headers={"User-Agent":"VulnusLab/1.0 (recon)"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    org=str(ctx.host).split(".")[0]
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("crates.io")
    cr=[{"name":c.get("name")} for c in (j.get("crates") or [])
        if org.lower() in str(c.get("name","")).lower()]
    ctx.state.update({"org":org,"crates":cr,"crate_count":len(cr)})
def _r_found(s):
    c=s.get("crates") or []
    if not c: return None
    return {"name":"%d Rust crate(s) match the org on crates.io"%len(c),"severity":"INFO","cwe":"CWE-1104",
        "evidence":", ".join(x["name"] for x in c[:6]),
        "remediation":"Verify ownership; look-alike crate names enable typosquat/dependency-confusion attacks."}
def _r_clean(s):
    if not s.get("reachable") or s.get("crates"): return None
    return {"name":"No org-matched crates","severity":"POSITIVE","evidence":"crates.io search: none for '%s'"%s.get("org","")}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Org term","org"),("Crates found","crate_count"),("Crates","crates")]
@router.post("/api/recon/cargo_go_typosquat")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="cargo_go_typosquat",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,flat_field_keys=["crates"])
def register(app): app.include_router(router)
