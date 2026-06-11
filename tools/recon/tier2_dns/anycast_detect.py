"""Anycast Detection v2 — VL-FORGE. RTT variance from multiple resolvers."""
import asyncio, time
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_PROBE_RESOLVERS=[
    ("Cloudflare-US","1.1.1.1"),
    ("Google-US","8.8.8.8"),
    ("Quad9-EU","9.9.9.9"),
    ("OpenDNS-US","208.67.222.222"),
]
async def _timed_query(host,resolver_ip):
    start=time.time()
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        r.nameservers=[resolver_ip]
        ans=await r.resolve(host,"A")
        elapsed_ms=int((time.time()-start)*1000)
        return {"resolver":resolver_ip,"answers":sorted([str(x).rstrip(".") for x in ans]),
                "rtt_ms":elapsed_ms,"ok":True}
    except Exception as e:
        return {"resolver":resolver_ip,"ok":False,"error":type(e).__name__}
async def gather(ctx):
    results=await asyncio.gather(*[_timed_query(ctx.host,ip) for _,ip in _PROBE_RESOLVERS])
    ok=[r for r in results if r.get("ok")]
    if not ok: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    ctx.source(f"resolvers-{len(ok)}")
    # Different geos returning SAME IPs → likely anycast
    answer_sets=set(tuple(r["answers"]) for r in ok)
    rtt_values=[r["rtt_ms"] for r in ok]
    same_answers=len(answer_sets)==1
    low_rtt_variance=max(rtt_values)-min(rtt_values)<50 if rtt_values else False
    anycast=same_answers and (len(ok)>=3) and (min(rtt_values)<100)
    ctx.state.update({"probe_results":results,"distinct_answer_sets":len(answer_sets),
        "rtt_range":[min(rtt_values),max(rtt_values)] if rtt_values else None,
        "anycast_likely":anycast,"same_answers":same_answers})
def _r_anycast(s):
    if not s.get("anycast_likely"): return None
    return {"name":"Anycast routing likely","severity":"INFO","cwe":"T1590.005",
        "evidence":f"Same A records from 3+ geos, RTT range: {s.get('rtt_range')}ms",
        "remediation":"Anycast = CDN/global LB. Probe origin via DNS history / SAN cert."}
def _r_unicast(s):
    if s.get("anycast_likely"): return None
    if not s.get("reachable"): return None
    return {"name":"Unicast routing (no anycast indicators)","severity":"INFO",
        "evidence":f"{s.get('distinct_answer_sets')} distinct answer sets across resolvers"}
def _r_geo_inconsistent(s):
    if s.get("distinct_answer_sets",0)<2: return None
    return {"name":"DNS returns different IPs by geo","severity":"INFO","cwe":"T1590.005",
        "evidence":f"{s.get('distinct_answer_sets')} answer sets — likely geo-DNS or split horizon"}
FINDING_RULES=[_r_anycast,_r_geo_inconsistent,_r_unicast]
INTEL_FIELDS=[("Anycast likely","anycast_likely"),("Distinct answers","distinct_answer_sets"),
    ("RTT range (ms)","rtt_range")]
@router.post("/api/recon/anycast_detect")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="anycast_detect",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["anycast_likely","probe_results"])
def register(app): app.include_router(router)
