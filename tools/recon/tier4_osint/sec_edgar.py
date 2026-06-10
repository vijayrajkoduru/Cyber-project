"""SEC EDGAR v2 — VL-FORGE. Public-company filings search."""
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
async def gather(ctx):
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="OSINT not applicable for IP / internal hostname"
        return
    org = get_org_name(ctx.host)
    if not org or org.lower() in _GENERIC_ORG_NAMES or len(org) < 4:
        ctx.state["skipped_reason"]=f"Org name '{org}' too generic to search SEC EDGAR without massive false-positive risk"
        return
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://efts.sec.gov/LATEST/search-index?q=%22{org}%22&dateRange=custom&startdt=2020-01-01&enddt=2026-12-31&forms=10-K,10-Q,8-K",
            timeout=12,headers={"User-Agent":"VulnusLab vulnuslab@vulnuslab.com"})
        if r.status_code==200:
            d=r.json()
            hits=d.get("hits",{}).get("hits",[])
            # ZERO-FP-V1: only count hits whose company name actually contains
            # the org as a token. EDGAR returns hits where the org appears
            # ANYWHERE in the filing text - that's why 'app' returned 100
            # filings from any company that mentioned "app" in a 10-Q.
            org_lc = org.lower()
            import re as _re
            verified = []
            for h in hits:
                names = h.get("_source",{}).get("display_names",[]) or []
                if any(_re.search(rf"\b{_re.escape(org_lc)}\b", str(n).lower()) for n in names):
                    verified.append(h)
            ctx.source(f"edgar-{len(verified)}")
            ctx.state["edgar_filings"]=[{"form":h["_source"].get("form"),
                "filed":h["_source"].get("file_date"),
                "company":h["_source"].get("display_names",[""])[0][:60]} for h in verified[:5]]
            ctx.state["filing_count"]=len(verified)
            ctx.state["raw_hit_count"]=len(hits)
    except: pass
def _r_public(s):
    n=s.get("filing_count",0)
    if n==0: return None
    return {"name":f"Target is/related-to public company ({n} SEC filings)","severity":"INFO","cwe":"T1591.002",
        "evidence":f"Recent: {(s.get('edgar_filings') or [{}])[0].get('form','')} on {(s.get('edgar_filings') or [{}])[0].get('filed','')}"}
def _r_clean(s):
    if s.get("filing_count",0)>0: return None
    return {"name":"No SEC filings for brand","severity":"POSITIVE",
        "evidence":"Not a US-listed public company"}
FINDING_RULES=[_r_public,_r_clean]
INTEL_FIELDS=[("SEC filings","filing_count"),("Sample","edgar_filings")]
@router.post("/api/recon/sec_edgar")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="sec_edgar",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["edgar_filings","filing_count"])
def register(app): app.include_router(router)
