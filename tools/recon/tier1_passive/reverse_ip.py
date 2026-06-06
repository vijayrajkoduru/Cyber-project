"""Reverse IP v2 — VL-FORGE. Find domains sharing same IP."""
import asyncio, requests
import dns.asyncresolver, dns.reversename
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
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver(); r.timeout=4; r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def _ptr(ip):
    try:
        r=dns.asyncresolver.Resolver(); r.timeout=3; r.lifetime=5
        rev=dns.reversename.from_address(ip)
        return [str(x).rstrip(".") for x in await r.resolve(rev,"PTR")]
    except: return []
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ips"]=ips
    ctx.source(f"a-{len(ips)}")
    # PTR for each IP
    ptr_results=await asyncio.gather(*[_ptr(ip) for ip in ips[:5]])
    ptr_data={ip:ptrs for ip,ptrs in zip(ips[:5],ptr_results) if ptrs}
    if ptr_data: ctx.source(f"ptr-{len(ptr_data)}")
    # ViewDNS reverse-ip API (free, limited)
    raw=await asyncio.to_thread(_g,f"https://viewdns.info/reverseip/?host={ctx.host}&t=1")
    shared=[]
    if raw:
        ctx.source("viewdns")
        # Parse HTML table for domain names
        import re
        rows=re.findall(r"<tr><td>([\w\.\-]+\.[a-z]{2,})</td>",raw or "")
        shared=[d for d in rows if d.lower()!=ctx.host.lower()][:20]
    ctx.state.update({"ptr_data":ptr_data,"ptr_count":len(ptr_data),
        "shared_domains":shared,"shared_count":len(shared)})
def _r_shared(s):
    n=s.get("shared_count") or 0
    if n<3: return None
    sev="INFO" if n<10 else "LOW"
    return {"name":f"{n} domains share this IP","severity":sev,"cwe":"T1590.005",
        "evidence":"Sample: "+", ".join((s.get("shared_domains") or [])[:5]),
        "remediation":"Shared hosting — investigate if neighbors are compromised."}
def _r_ptr(s):
    pd=s.get("ptr_data") or {}
    if not pd: return None
    sample={k:v[:2] for k,v in list(pd.items())[:3]}
    return {"name":f"PTR records present for {len(pd)} IP(s)","severity":"INFO",
        "evidence":f"Sample: {sample}"}
def _r_no_ptr(s):
    if s.get("ptr_count"): return None
    if not s.get("ips"): return None
    return {"name":"No PTR records (reverse DNS not configured)","severity":"LOW","cwe":"CWE-200",
        "evidence":"Reverse DNS lookups failed for all IPs",
        "remediation":"PTR records help email deliverability + log readability."}
def _r_chain_handoff(s):
    shared=s.get("shared_domains") or []
    n=len(shared)
    ips=s.get("ips") or []
    if n==0: return None
    chain_next=[]
    if "tcp_port_scan" not in chain_next: chain_next.append("tcp_port_scan")
    if "subdomain_bruteforce" not in chain_next: chain_next.append("subdomain_bruteforce")
    if n>20 and "cloudfront_disco" not in chain_next: chain_next.append("cloudfront_disco")
    hv=[d for d in shared if any(k in d.lower() for k in ("admin","dev","staging","test","internal"))]
    if hv:
        for sc in ("exposed_env_scan","tech_stack_detect"):
            if sc not in chain_next: chain_next.append(sc)
    cloud_ranges=("52.","54.","13.","18.","35.","34.","104.","23.")
    if ips and any(ip.startswith(cloud_ranges) for ip in ips):
        if "s3_bucket_enum" not in chain_next: chain_next.append("s3_bucket_enum")
    tlds=set()
    for d in shared:
        parts=d.rsplit(".",1)
        if len(parts)==2: tlds.add(parts[1].lower())
    if len(tlds)>1 and "dnstwist" not in chain_next: chain_next.append("dnstwist")
    if not chain_next: return None
    return {
        "name":"Cross-module chain handoff - co-hosted sites discovered for follow-up",
        "severity":"INFO",
        "evidence":f"Found {n} co-hosted site(s); suggests {len(chain_next)} follow-up scanner(s)",
        "remediation":"Each co-hosted site is independent attack surface. Run port_scan + subdomain enum + tech stack per host.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"reverse_ip_to_cohost_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_shared,_r_ptr,_r_no_ptr,_r_chain_handoff]
INTEL_FIELDS=[("IPs","ips"),("PTR records","ptr_count"),("Shared domains","shared_count")]
@router.post("/api/recon/reverse_ip")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="reverse_ip",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["ips","ptr_data","shared_domains"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "reverse_ip", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("reverse_ip", _chain_callable)
