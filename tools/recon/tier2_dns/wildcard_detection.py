"""Wildcard DNS Detection v2 — VL-FORGE. Random-subdomain probe."""
import asyncio, secrets
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _q(h,rt="A"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,rt)]
    except: return []
async def gather(ctx):
    h=ctx.host
    # Generate 3 random subdomains
    randoms=[f"vlrandom-{secrets.token_hex(6)}.{h}" for _ in range(3)]
    results=await asyncio.gather(*[_q(r) for r in randoms])
    apex_a=await _q(h)
    ctx.state["apex_a"]=apex_a
    ctx.state["reachable"]=bool(apex_a)
    if apex_a: ctx.source("apex-a")
    # Wildcard if all 3 random resolve to same IPs
    resolves=[set(r) for r in results if r]
    has_wildcard=len(resolves)>=2 and all(r==resolves[0] for r in resolves)
    if has_wildcard:
        ctx.source(f"wildcard-detected")
        ctx.state["wildcard_ips"]=sorted(resolves[0])
    ctx.state.update({"random_test_results":[{"host":r,"resolves":list(res)} for r,res in zip(randoms,results)],
        "wildcard_detected":has_wildcard,
        "random_count_resolving":sum(1 for r in results if r)})
def _r_wildcard(s):
    if not s.get("wildcard_detected"): return None
    return {"name":"Wildcard DNS detected","severity":"MEDIUM","cwe":"CWE-665",
        "evidence":f"All random subdomains resolve to: {s.get('wildcard_ips')}",
        "remediation":"Wildcard *.example.com → IP catches typos but defeats subdomain enumeration. Consider explicit records only."}
def _r_no_wildcard(s):
    if s.get("wildcard_detected"): return None
    if not s.get("reachable"): return None
    return {"name":"No wildcard DNS","severity":"POSITIVE",
        "evidence":"Random subdomains return NXDOMAIN — subdomain enumeration meaningful"}
FINDING_RULES=[_r_wildcard,_r_no_wildcard]
INTEL_FIELDS=[("Apex A","apex_a"),("Wildcard","wildcard_detected"),("Wildcard IPs","wildcard_ips")]
@router.post("/api/recon/wildcard_detection")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="wildcard_detection",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["wildcard_detected","wildcard_ips"])
def register(app): app.include_router(router)
