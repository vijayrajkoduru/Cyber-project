"""apple_store_search — VL-FORGE. Own-code (iTunes Search API, no key): org iOS apps."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _search(term):
    try:
        r=requests.get("https://itunes.apple.com/search",
            params={"term":term,"entity":"software","limit":15,"country":"us"},
            timeout=8, headers={"User-Agent":"VulnusLab/1.0"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    org=str(ctx.host).split(".")[0]
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("itunes")
    apps=[{"name":x.get("trackName"),"seller":x.get("sellerName"),"bundle":x.get("bundleId")}
          for x in (j.get("results") or [])
          if org.lower() in (str(x.get("sellerName",""))+str(x.get("trackName",""))+str(x.get("bundleId",""))).lower()]
    ctx.state.update({"org":org,"apps":apps,"app_count":len(apps)})
def _r_found(s):
    a=s.get("apps") or []
    if not a: return None
    return {"name":"%d iOS app(s) match the org on the App Store"%len(a),"severity":"INFO","cwe":"CWE-200",
        "evidence":", ".join("%s (%s)"%(x["name"],x.get("bundle") or "?") for x in a[:5]),
        "remediation":"Confirm official; mobile apps expand attack surface (keys/endpoints in the binary)."}
def _r_clean(s):
    if not s.get("reachable") or s.get("apps"): return None
    return {"name":"No org-matched iOS apps","severity":"POSITIVE","evidence":"iTunes Search: none for '%s'"%s.get("org","")}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Org term","org"),("Apps found","app_count"),("Apps","apps")]
@router.post("/api/recon/apple_store_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="apple_store_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,flat_field_keys=["apps"])
def register(app): app.include_router(router)
