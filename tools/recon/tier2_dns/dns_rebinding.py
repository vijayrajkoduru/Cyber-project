"""DNS Rebinding v2 — VL-FORGE. Low-TTL + private-IP A record check."""
import asyncio, ipaddress
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _q(h,rt="A"):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        ans=await r.resolve(h,rt)
        ttl=ans.rrset.ttl
        return [str(x).rstrip(".") for x in ans], ttl
    except: return [],None
async def gather(ctx):
    a,ttl=await _q(ctx.host)
    if not a: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["a_records"]=a; ctx.state["ttl"]=ttl
    ctx.source(f"a-ttl-{ttl}")
    private_ips=[]
    for ip in a:
        try:
            ipa=ipaddress.ip_address(ip)
            if ipa.is_private or ipa.is_loopback or ipa.is_link_local:
                private_ips.append(ip)
        except: pass
    ctx.state.update({"private_ips":private_ips,"low_ttl":ttl is not None and ttl<60,
        "rebinding_risk":bool(private_ips) and (ttl is not None and ttl<60)})
def _r_active_rebind(s):
    if not s.get("rebinding_risk"): return None
    return {"name":"DNS rebinding attack surface present","severity":"HIGH","cvss":7.5,
        "cwe":"CWE-350","owasp":"A05:2021",
        "evidence":f"TTL={s.get('ttl')}s + private IPs in A: {', '.join(s.get('private_ips') or [])}",
        "remediation":"DNS should not return private IPs externally. Block private-IP DNS responses at resolver."}
def _r_private_ip(s):
    p=s.get("private_ips") or []
    if not p or s.get("rebinding_risk"): return None
    return {"name":f"Private IPs in public DNS ({len(p)})","severity":"MEDIUM","cwe":"CWE-200",
        "evidence":", ".join(p),
        "remediation":"Public DNS leaking RFC1918 addresses — split-horizon DNS recommended."}
def _r_low_ttl(s):
    if not s.get("low_ttl") or s.get("rebinding_risk"): return None
    return {"name":f"Low DNS TTL ({s.get('ttl')}s)","severity":"INFO",
        "evidence":"Short TTLs enable fast failover but also rebinding attack windows"}
FINDING_RULES=[_r_active_rebind,_r_private_ip,_r_low_ttl]
INTEL_FIELDS=[("A records","a_records"),("TTL","ttl"),
    ("Private IPs","private_ips"),("Rebinding risk","rebinding_risk")]
@router.post("/api/recon/dns_rebinding")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="dns_rebinding",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["a_records","ttl","private_ips"])
def register(app): app.include_router(router)
