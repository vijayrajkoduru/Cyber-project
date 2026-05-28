"""DNS Cache Snooping v2 — VL-FORGE. Non-recursive query check."""
import asyncio
import dns.message, dns.query, dns.flags, dns.name
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_PROBES=["google.com","facebook.com","amazon.com","cloudflare.com"]
async def _q_nonrecursive(host,target_name):
    """Query target's NS with RD=0 (non-recursive)."""
    try:
        m=dns.message.make_query(target_name,"A")
        m.flags &= ~dns.flags.RD  # disable recursion desired
        r=await asyncio.to_thread(dns.query.udp,m,host,timeout=4)
        return r.answer  # empty if not cached
    except Exception:
        return None
async def _resolve_ns(h):
    import dns.asyncresolver
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        ns_records=await r.resolve(h,"NS")
        ns_list=[str(x).rstrip(".") for x in ns_records]
        # Resolve NS to IPs
        ns_ips=[]
        for n in ns_list[:2]:
            try:
                a=await r.resolve(n,"A")
                ns_ips.extend([str(x).rstrip(".") for x in a])
            except: pass
        return ns_ips
    except: return []
async def gather(ctx):
    ns_ips=await _resolve_ns(ctx.host)
    if not ns_ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ns_ips_tested"]=ns_ips[:2]
    ctx.source(f"ns-ips-{len(ns_ips)}")
    cached_probes=[]
    for ns_ip in ns_ips[:2]:
        for probe in _PROBES:
            ans=await _q_nonrecursive(ns_ip,probe)
            if ans:
                cached_probes.append({"ns":ns_ip,"probe":probe,"cached":True})
    ctx.state.update({"cached_probes":cached_probes,"vulnerable":bool(cached_probes)})
def _r_vuln(s):
    cp=s.get("cached_probes") or []
    if not cp: return None
    return {"name":f"DNS cache snooping possible ({len(cp)} probes cached)","severity":"MEDIUM",
        "cvss":4.5,"cwe":"CWE-200","owasp":"A05:2021",
        "evidence":f"Non-recursive queries returned cached responses: {[c['probe'] for c in cp[:3]]}",
        "remediation":"Disable recursion on authoritative-only NS. bind: 'recursion no;'"}
def _r_safe(s):
    if (s.get("cached_probes") or []): return None
    if not s.get("ns_ips_tested"): return None
    return {"name":"DNS cache snooping not feasible","severity":"POSITIVE",
        "evidence":f"NS rejected non-recursive queries for {len(_PROBES)} probes"}
FINDING_RULES=[_r_vuln,_r_safe]
INTEL_FIELDS=[("NS tested","ns_ips_tested"),("Cached probes","cached_probes")]
@router.post("/api/recon/cache_snooping")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="cache_snooping",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["vulnerable","cached_probes"])
def register(app): app.include_router(router)
