"""Wayback Timeline v2 — VL-FORGE. Web archive snapshot history."""
import asyncio, requests, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=15):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    t1,t2=await asyncio.gather(
        asyncio.to_thread(_g,f"http://web.archive.org/cdx/search/cdx?url={host}&output=json&limit=200"),
        asyncio.to_thread(_g,f"http://web.archive.org/cdx/search/cdx?url=*.{host}&output=json&limit=200"))
    snapshots=[]; years=set()
    for txt in [t1,t2]:
        if not txt: continue
        ctx.source("wayback")
        try: data=json.loads(txt)
        except: continue
        if data and len(data)>1:
            for row in data[1:]:
                if len(row)>=6:
                    ts=row[1]; url=row[2]; mime=row[3]; status=row[4]
                    if ts and len(ts)>=4: years.add(ts[:4])
                    snapshots.append({"ts":ts,"url":url[:120],"status":status})
    ctx.state["snapshot_count"]=len(snapshots)
    ctx.state["years_covered"]=sorted(years)
    ctx.state["first_snapshot"]=min((s["ts"] for s in snapshots),default=None) if snapshots else None
    ctx.state["last_snapshot"]=max((s["ts"] for s in snapshots),default=None) if snapshots else None
    ctx.state["sample_urls"]=list({s["url"] for s in snapshots})[:10]
    ctx.state["reachable"]=bool(snapshots)
def _r_history(s):
    n=s.get("snapshot_count") or 0
    if n==0: return None
    years=len(s.get("years_covered") or [])
    return {"name":f"{n} Wayback snapshots across {years} year(s)","severity":"INFO","cwe":"T1596",
        "evidence":f"First: {s.get('first_snapshot')} | Last: {s.get('last_snapshot')}",
        "remediation":"Review historical snapshots for forgotten endpoints / leaked data."}
def _r_old(s):
    """VL-VERIFY (zero-FP): existence of a long Wayback history is NOT a
    security finding by itself - any major site (google.com since 1998,
    wikipedia.org, etc.) would trip a LOW severity flag for nothing.
    The audit-old-snapshots-for-secrets advice still has value, so we keep
    surfacing the information - just at INFO not LOW, with no CVSS."""
    fs=s.get("first_snapshot","") or ""
    if not fs or len(fs)<4: return None
    yr=int(fs[:4])
    if yr>2010: return None
    return {"name":f"Long Wayback history (since {yr})","severity":"INFO",
        "evidence":f"Site indexed since {fs} - manual audit of early snapshots "
                    f"can surface accidentally-committed secrets / API keys.",
        "remediation":"Audit early snapshots for hardcoded creds / API keys."}
def _r_clean(s):
    if (s.get("snapshot_count") or 0)>0: return None
    return {"name":"No Wayback history","severity":"POSITIVE",
        "evidence":"Domain not archived — minimal historical footprint"}
FINDING_RULES=[_r_old,_r_history,_r_clean]
INTEL_FIELDS=[("Snapshots","snapshot_count"),("Years","years_covered"),
    ("First","first_snapshot"),("Last","last_snapshot")]
@router.post("/api/recon/wayback_timeline")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="wayback_timeline",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["snapshot_count","sample_urls","first_snapshot"])
def register(app): app.include_router(router)
