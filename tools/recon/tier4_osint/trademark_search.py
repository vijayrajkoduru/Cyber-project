"""Trademark Search v2 — VL-FORGE. USPTO + EUIPO free APIs."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    org=ctx.host.split(".")[0]
    try:
        # USPTO Trademark Search API (free)
        r=await asyncio.to_thread(requests.get,
            f"https://tsdrapi.uspto.gov/ts/cd/casestatus/sn{org}/info.json",
            timeout=12,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200:
            d=r.json()
            ctx.source("uspto")
            ctx.state["uspto_result"]=d
            ctx.state["uspto_found"]=bool(d)
    except Exception: pass
    # OpenCorporates as fallback (free) — query company name
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.opencorporates.com/v0.4/companies/search?q={org}",
            timeout=12)
        if r.status_code==200:
            d=r.json()
            companies=d.get("results",{}).get("companies",[])
            ctx.state["opencorporates_matches"]=[{"name":c["company"].get("name"),
                "jurisdiction":c["company"].get("jurisdiction_code"),
                "status":c["company"].get("current_status")} for c in companies[:5]]
            if companies: ctx.source(f"opencorporates-{len(companies)}")
    except Exception: pass
def _r_oc(s):
    matches=s.get("opencorporates_matches") or []
    if not matches: return None
    return {"name":f"{len(matches)} registered companies match brand","severity":"INFO","cwe":"T1591.002",
        "evidence":f"Top: {matches[0].get('name','')} ({matches[0].get('jurisdiction','')})"}
def _r_uspto(s):
    if not s.get("uspto_found"): return None
    return {"name":"USPTO trademark filing found","severity":"INFO",
        "evidence":"Trademark records public — confirms legal entity"}
FINDING_RULES=[_r_oc,_r_uspto]
INTEL_FIELDS=[("USPTO match","uspto_found"),("OpenCorporates matches","opencorporates_matches")]
@router.post("/api/recon/trademark_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="trademark_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["uspto_result","opencorporates_matches"])
def register(app): app.include_router(router)
