"""apple_store_search — VL-FORGE. Own-code (iTunes Search API, no key): org iOS apps."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._targeting import get_org_name, can_do_osint
router=APIRouter()
_GENERIC_ORG_NAMES = frozenset({
    "app","api","www","web","dev","staging","test","demo","admin",
    "portal","site","shop","blog","mail","cdn","static","assets",
})
def _search(term):
    try:
        r=requests.get("https://itunes.apple.com/search",
            params={"term":term,"entity":"software","limit":15,"country":"us"},
            timeout=8, headers={"User-Agent":"VulnusLab/1.0"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="OSINT not applicable for IP / internal hostname"
        return
    org = get_org_name(ctx.host)
    if not org or org.lower() in _GENERIC_ORG_NAMES or len(org) < 4:
        ctx.state["skipped_reason"]=f"Org name '{org}' too generic to search App Store without massive false-positive risk"
        return
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("itunes")
    # Strict: bundle ID must contain org as a token (e.g. com.vulnuslab.app)
    # OR seller name must match org. Track name match alone is not enough -
    # WhatsApp matched "app" via trackName "WhatsApp" -> obvious FP.
    org_lc = org.lower()
    def _is_match(x):
        seller = str(x.get("sellerName","")).lower()
        bundle = str(x.get("bundleId","")).lower()
        # Bundle ID is reverse-DNS; org must appear as a path segment
        if org_lc and any(seg == org_lc for seg in bundle.split(".")):
            return True
        # Seller name must contain org as a whole word, not substring
        import re as _re
        if _re.search(rf"\b{_re.escape(org_lc)}\b", seller):
            return True
        return False
    apps=[{"name":x.get("trackName"),"seller":x.get("sellerName"),"bundle":x.get("bundleId")}
          for x in (j.get("results") or []) if _is_match(x)]
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
