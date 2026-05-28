"""Reverse NS v2 — VL-FORGE. Find domains using same nameservers."""
import asyncio, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    try:
        r=dns.asyncresolver.Resolver(); r.timeout=4; r.lifetime=6
        ns=[str(x).rstrip(".") for x in await r.resolve(host,"NS")]
    except: ns=[]
    if not ns: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["nameservers"]=ns
    ctx.source(f"ns-{len(ns)}")
    # Use viewdns to find other domains on these NS
    import re
    domain_sets={}
    for n in ns[:2]:
        raw=await asyncio.to_thread(_g,f"https://viewdns.info/reversens/?ns={n}")
        if raw:
            ctx.source(f"viewdns-{n}")
            doms=re.findall(r"<tr><td>([\w\.\-]+\.[a-z]{2,})</td>",raw)
            doms=[d for d in doms if d.lower()!=host.lower()][:20]
            domain_sets[n]=doms
    all_shared=set()
    for v in domain_sets.values(): all_shared.update(v)
    ctx.state.update({"shared_by_ns":domain_sets,"total_shared":sorted(all_shared)[:20],
        "shared_count":len(all_shared)})
def _r_shared(s):
    n=s.get("shared_count") or 0
    if n<5: return None
    sev="INFO" if n<20 else "LOW"
    return {"name":f"{n} domains share these NS","severity":sev,"cwe":"T1590.002",
        "evidence":"Sample: "+", ".join((s.get("total_shared") or [])[:5]),
        "remediation":"Shared NS — investigate sister domains for compromise."}
def _r_dedicated(s):
    n=s.get("shared_count") or 0
    if n>0: return None
    if not s.get("nameservers"): return None
    return {"name":"NS appear dedicated (no shared domains found)","severity":"POSITIVE",
        "evidence":"viewdns reverse-NS returned 0 results"}
FINDING_RULES=[_r_shared,_r_dedicated]
INTEL_FIELDS=[("Nameservers","nameservers"),("Shared domains","shared_count")]
@router.post("/api/recon/reverse_ns")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="reverse_ns",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["nameservers","total_shared","shared_count"])
def register(app): app.include_router(router)
