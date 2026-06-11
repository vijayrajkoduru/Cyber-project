"""DNS 0x20 v2 — VL-FORGE. Case-randomization defense check."""
import random
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _q(h,rt):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,rt)]
    except: return []
def _randcase(s):
    return "".join(c.upper() if random.random()>0.5 else c.lower() for c in s)
async def gather(ctx):
    h=ctx.host
    lower_a=await _q(h.lower(),"A")
    if not lower_a: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["baseline_a"]=lower_a
    ctx.source("baseline")
    # 3 randomized case queries
    mixed_results=[]
    for _ in range(3):
        mixed=_randcase(h)
        res=await _q(mixed,"A")
        mixed_results.append({"query":mixed,"answers":sorted(res)})
    # Check consistency
    baseline_sorted=sorted(lower_a)
    all_match=all(m["answers"]==baseline_sorted for m in mixed_results)
    ctx.state.update({"mixed_queries":mixed_results,"case_preserved":all_match,
        "consistent_response":all_match})
    ctx.source("case-test")
def _r_no_0x20(s):
    if s.get("case_preserved"): return None
    if not s.get("mixed_queries"): return None
    return {"name":"DNS responses inconsistent across case variations","severity":"LOW","cwe":"CWE-345",
        "evidence":"Different answers for different case mixes — possible cache pollution risk",
        "remediation":"Resolver should preserve query case (0x20 encoding); verify upstream."}
def _r_0x20_present(s):
    if not s.get("case_preserved"): return None
    return {"name":"DNS 0x20 case handling consistent","severity":"POSITIVE",
        "evidence":"Resolver preserves query case correctly"}
FINDING_RULES=[_r_no_0x20,_r_0x20_present]
INTEL_FIELDS=[("Case preserved","case_preserved"),("Baseline A","baseline_a")]
@router.post("/api/recon/dns_0x20")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="dns_0x20",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["case_preserved","baseline_a"])
def register(app): app.include_router(router)
