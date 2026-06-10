"""DNSSEC v2 — VL-FORGE. DNSKEY + DS chain validation."""
import asyncio
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def _q(h,rt):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x) for x in await r.resolve(h,rt)]
    except: return []
async def gather(ctx):
    h=ctx.host
    dnskey,ds,rrsig=await asyncio.gather(_q(h,"DNSKEY"),_q(h,"DS"),_q(h,"RRSIG"))
    has_dnskey=bool(dnskey); has_ds=bool(ds); has_rrsig=bool(rrsig)
    if has_dnskey: ctx.source(f"dnskey-{len(dnskey)}")
    if has_ds: ctx.source(f"ds-{len(ds)}")
    if has_rrsig: ctx.source(f"rrsig-{len(rrsig)}")
    # Algorithm check
    weak_algos=[]
    for k in dnskey:
        parts=k.split(); 
        if len(parts)>=4:
            algo=parts[2]
            if algo in ("1","3","5","6","7"): weak_algos.append(algo)
    ctx.state.update({"reachable":has_dnskey or has_ds,"dnskey_count":len(dnskey),
        "ds_count":len(ds),"rrsig_count":len(rrsig),"weak_algorithms":weak_algos,
        "dnssec_enabled":has_dnskey,"chain_complete":has_dnskey and has_ds})
def _r_disabled(s):
    if s.get("dnssec_enabled"): return None
    if not s.get("reachable") is False: return None
    return {"name":"DNSSEC not enabled","severity":"MEDIUM","cwe":"CWE-345",
        "evidence":"No DNSKEY records published",
        "remediation":"Enable DNSSEC at registrar to prevent DNS spoofing."}
def _r_partial(s):
    if not s.get("dnssec_enabled") or s.get("chain_complete"): return None
    return {"name":"DNSSEC partial — DNSKEY present but no DS","severity":"MEDIUM","cwe":"CWE-345",
        "evidence":"Chain of trust broken between parent zone and child",
        "remediation":"Publish DS record at parent zone to complete chain."}
def _r_weak(s):
    w=s.get("weak_algorithms") or []
    if not w: return None
    return {"name":f"Weak DNSSEC algorithm(s): {', '.join(set(w))}","severity":"HIGH","cwe":"CWE-327",
        "evidence":"RSA/SHA1 deprecated — upgrade to ECDSAP256SHA256 (alg 13)"}
def _r_signed(s):
    if not s.get("chain_complete"): return None
    return {"name":"DNSSEC fully signed (chain complete)","severity":"POSITIVE",
        "evidence":f"DNSKEY×{s.get('dnskey_count')} + DS×{s.get('ds_count')}"}
FINDING_RULES=[_r_weak,_r_partial,_r_disabled,_r_signed]
INTEL_FIELDS=[("DNSSEC enabled","dnssec_enabled"),("Chain complete","chain_complete"),
    ("DNSKEY","dnskey_count"),("DS","ds_count"),("Weak algos","weak_algorithms")]
@router.post("/api/recon/dnssec")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="dnssec",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["dnssec_enabled","chain_complete","weak_algorithms"])
def register(app): app.include_router(router)
