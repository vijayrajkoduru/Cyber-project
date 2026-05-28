"""Load Balancer Detection v2 — VL-FORGE. TTL variance + multi-A + HTTP signatures."""
import asyncio, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _q(h,rt="A"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        ans=await r.resolve(h,rt)
        return [str(x).rstrip(".") for x in ans], ans.rrset.ttl
    except: return [],None
def _http_headers(url):
    try:
        r=requests.head(url,timeout=6,verify=False,allow_redirects=True,
            headers={"User-Agent":"VulnusLab/1.0"})
        return dict(r.headers)
    except: return {}
async def gather(ctx):
    a,ttl=await _q(ctx.host)
    if not a: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["a_records"]=a; ctx.state["ttl"]=ttl
    if a: ctx.source(f"a-{len(a)}-ttl-{ttl}")
    headers=await asyncio.to_thread(_http_headers,web_url(ctx.host))
    if headers: ctx.source("http-headers")
    # LB indicators in headers
    lb_indicators={
        "via":"Generic proxy",
        "x-forwarded-for":"X-Forwarded-For chain",
        "x-real-ip":"X-Real-IP header",
        "x-load-balancer":"LB header",
        "x-served-by":"Fastly/Varnish",
        "x-cache":"Caching LB",
        "server":"Server header"
    }
    lb_hits=[]
    for k,v in lb_indicators.items():
        if k in [h.lower() for h in headers]:
            actual=next((headers[h] for h in headers if h.lower()==k),"")
            lb_hits.append({"header":k,"value":actual[:80],"meaning":v})
    multi_a=len(a)>1
    short_ttl=ttl is not None and ttl<60
    ctx.state.update({"http_headers":{k:v[:100] for k,v in headers.items()},
        "lb_header_hits":lb_hits,"multi_a":multi_a,"short_ttl":short_ttl,
        "lb_detected":multi_a or bool(lb_hits) or short_ttl})
def _r_lb(s):
    if not s.get("lb_detected"): return None
    reasons=[]
    if s.get("multi_a"): reasons.append(f"multiple A ({len(s.get('a_records',[]))})")
    if s.get("short_ttl"): reasons.append(f"short TTL ({s.get('ttl')}s)")
    if s.get("lb_header_hits"): reasons.append(f"{len(s['lb_header_hits'])} LB headers")
    return {"name":"Load balancer / proxy detected","severity":"INFO","cwe":"T1590.005",
        "evidence":"; ".join(reasons),
        "remediation":"Information only — LB presence affects exploitation strategies."}
def _r_direct(s):
    if s.get("lb_detected"): return None
    if not s.get("reachable"): return None
    return {"name":"No load balancer detected","severity":"INFO",
        "evidence":"Single A record + long TTL + no LB headers"}
FINDING_RULES=[_r_lb,_r_direct]
INTEL_FIELDS=[("A records","a_records"),("TTL","ttl"),
    ("Multi-A","multi_a"),("LB headers","lb_header_hits"),("LB detected","lb_detected")]
@router.post("/api/recon/lb_detection")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="lb_detection",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["a_records","lb_detected","lb_header_hits"])
def register(app): app.include_router(router)
