"""Zone Transfer v2 — VL-FORGE. AXFR attempt against each NS."""
import asyncio
import dns.asyncresolver, dns.query, dns.zone, dns.exception
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _ns(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return sorted(str(x).rstrip(".") for x in await r.resolve(h,"NS"))
    except: return []
def _axfr(host,ns):
    try:
        xfr=dns.query.xfr(ns,host,timeout=6,lifetime=10)
        zone=dns.zone.from_xfr(xfr)
        records=[]
        for name,node in zone.nodes.items():
            for rdataset in node.rdatasets:
                records.append(f"{name} {rdataset.rdtype} {str(rdataset).split()[-1][:50]}")
        return {"ns":ns,"success":True,"records":records[:50],"count":len(records)}
    except Exception as e:
        return {"ns":ns,"success":False,"error":type(e).__name__}
async def gather(ctx):
    ns_list=await _ns(ctx.host)
    if not ns_list: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ns_list"]=ns_list
    ctx.source(f"ns-{len(ns_list)}")
    results=await asyncio.gather(*[asyncio.to_thread(_axfr,ctx.host,n) for n in ns_list])
    successes=[r for r in results if r.get("success")]
    if successes: ctx.source(f"axfr-success-{len(successes)}")
    ctx.state.update({"transfer_attempts":results,"vulnerable":bool(successes),
        "leaked_records":sum(r.get("count",0) for r in successes),
        "vulnerable_ns":[r["ns"] for r in successes]})
def _r_vuln(s):
    if not s.get("vulnerable"): return None
    return {"name":f"DNS zone transfer ALLOWED on {len(s.get('vulnerable_ns',[]))} NS","severity":"CRITICAL",
        "cvss":9.0,"cwe":"CWE-200","owasp":"A05:2021",
        "evidence":f"Vulnerable NS: {', '.join(s.get('vulnerable_ns') or [])} — leaked {s.get('leaked_records',0)} records",
        "remediation":"Disable AXFR. nginx-bind: 'allow-transfer { trusted-ips; };' | Microsoft DNS: restrict zone transfers."}
def _r_safe(s):
    if s.get("vulnerable"): return None
    if not s.get("ns_list"): return None
    return {"name":"AXFR refused on all NS","severity":"POSITIVE",
        "evidence":f"All {len(s['ns_list'])} authoritative NS rejected zone transfer"}
def _r_chain_handoff(s):
    if not s.get("ns_list"): return None
    chain_next=[]
    vulnerable=bool(s.get("vulnerable"))
    leaked=int(s.get("leaked_records",0) or 0)
    vuln_ns=s.get("vulnerable_ns") or []
    attempts=s.get("transfer_attempts") or []
    ns_responded=bool(s.get("ns_list"))
    refused=[a for a in attempts if not a.get("success")]
    refused_codes={a.get("error","") for a in refused}
    dnssec_present=any("DNSSEC" in (a.get("error","") or "") for a in attempts) or any(
        "NSEC" in str(a) for a in attempts)
    internal_markers=("10.","172.","192.168.","internal","corp","ad.","dc.")
    open_internal=any(any(m in (ns or "").lower() for m in internal_markers) for ns in vuln_ns)

    if vulnerable and leaked>0:
        for s_name in ("subdomain_bruteforce","tcp_port_scan","subdomain_takeover","dns_records"):
            if s_name not in chain_next: chain_next.append(s_name)
    if (not vulnerable) and ns_responded and refused:
        if "nsec_walking" not in chain_next: chain_next.append("nsec_walking")
    if dnssec_present and not vulnerable:
        for s_name in ("dnssec","nsec_walking"):
            if s_name not in chain_next: chain_next.append(s_name)
    if vulnerable and open_internal:
        if "smb_netbios_enum" not in chain_next: chain_next.append("smb_netbios_enum")

    if not chain_next: return None
    axfr_result=("succeeded" if vulnerable else
                 ("refused" if refused else "no-response"))
    return {
        "name":"Cross-module chain handoff - zone transfer posture suggests follow-up",
        "severity":"INFO",
        "evidence":f"AXFR result: {axfr_result}; leaked records: {leaked}; suggests {len(chain_next)} follow-up scanner(s)",
        "remediation":"Leaked zone = full DNS topology. If refused, NSEC walking + subdomain brute still reveal records.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"axfr_to_dns_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_vuln,_r_safe,_r_chain_handoff]
INTEL_FIELDS=[("NS list","ns_list"),("Vulnerable","vulnerable"),
    ("Leaked records","leaked_records"),("Vulnerable NS","vulnerable_ns")]
@router.post("/api/recon/zone_transfer")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="zone_transfer",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["vulnerable","ns_list","vulnerable_ns"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners trigger us via
#  _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "zone_transfer", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("zone_transfer", _chain_callable)
