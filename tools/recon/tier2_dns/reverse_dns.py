"""Reverse DNS v2 — VL-FORGE. PTR records for resolved IPs + forward-confirmed check."""
import asyncio
import dns.asyncresolver, dns.reversename
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _q(h,rt):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,rt)]
    except: return []
async def gather(ctx):
    a=await _q(ctx.host,"A")
    if not a: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["a_records"]=a
    # PTR for each IP
    ptr_tasks=[]
    for ip in a[:5]:
        try:
            rev=dns.reversename.from_address(ip)
            ptr_tasks.append(_q(rev,"PTR"))
        except: ptr_tasks.append(None)
    ptr_results=await asyncio.gather(*[t if t else asyncio.sleep(0,result=[]) for t in ptr_tasks])
    ptr_map={ip:p for ip,p in zip(a[:5],ptr_results)}
    # Forward-confirmed check (FCrDNS)
    fcrdns_results=[]
    for ip,ptrs in ptr_map.items():
        for ptr in ptrs:
            fwd=await _q(ptr,"A")
            fcrdns_results.append({"ip":ip,"ptr":ptr,"forward":fwd,"confirmed":ip in fwd})
    if any(ptr_map.values()): ctx.source(f"ptr-{sum(1 for p in ptr_map.values() if p)}")
    ctx.state.update({"ptr_map":ptr_map,"fcrdns_checks":fcrdns_results,
        "ptr_count":sum(1 for p in ptr_map.values() if p),
        "fcrdns_failures":[f for f in fcrdns_results if not f["confirmed"]]})
def _r_no_ptr(s):
    if s.get("ptr_count"): return None
    if not s.get("a_records"): return None
    return {"name":"No PTR records (reverse DNS missing)","severity":"LOW","cwe":"CWE-200",
        "evidence":"All resolved IPs lack PTR — hurts email deliverability + log readability",
        "remediation":"Configure reverse DNS at hosting provider / IP owner."}
def _r_fcrdns_fail(s):
    fails=s.get("fcrdns_failures") or []
    if not fails: return None
    sample=[f"{x['ip']}->{x['ptr']}->{x['forward']}" for x in fails[:2]]
    return {"name":f"Forward-confirmed rDNS failures ({len(fails)})","severity":"LOW","cwe":"CWE-345",
        "evidence":f"PTR->A doesn't loop back: {sample}",
        "remediation":"PTR + A should match. Coordinate with hosting provider."}
def _r_ptr_present(s):
    if not s.get("ptr_count"): return None
    return {"name":f"PTR records configured ({s['ptr_count']})","severity":"POSITIVE",
        "evidence":f"Sample: {dict(list(s.get('ptr_map',{}).items())[:2])}"}
FINDING_RULES=[_r_no_ptr,_r_fcrdns_fail,_r_ptr_present]
INTEL_FIELDS=[("A records","a_records"),("PTR count","ptr_count"),("PTR map","ptr_map")]
@router.post("/api/recon/reverse_dns")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="reverse_dns",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["a_records","ptr_map"])
def register(app): app.include_router(router)
