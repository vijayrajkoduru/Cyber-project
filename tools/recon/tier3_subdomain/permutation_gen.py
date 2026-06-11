"""Permutation Gen v2 — VL-FORGE. Alteration patterns from known subs."""
import asyncio
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_BASES=["api","www","admin","app","dev","staging","prod"]
_AFFIXES=["1","2","01","02","-new","-old","-test","-dev","-staging","-prod","-eu","-us","-eu1","-us1","-1","-2","2024","2025","2026"]
async def _q(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=3;r.lifetime=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def gather(ctx):
    permutations=set()
    for base in _BASES:
        for affix in _AFFIXES:
            permutations.add(f"{base}{affix}")
            permutations.add(f"{base}-{affix.lstrip('-')}")
            permutations.add(f"{affix.lstrip('-')}{base}")
    permutations=sorted(permutations)
    ctx.state["permutations_generated"]=len(permutations)
    ctx.source(f"permutations-{len(permutations)}")
    sem=asyncio.Semaphore(30)
    async def one(p):
        async with sem:
            sub=f"{p}.{ctx.host}"; ips=await _q(sub)
            return {"subdomain":sub,"ips":ips,"pattern":p} if ips else None
    res=await asyncio.gather(*[one(p) for p in permutations])
    found=[r for r in res if r]
    ctx.state["found"]=found; ctx.state["found_count"]=len(found)
    if found: ctx.source(f"resolved-{len(found)}")
def _r_versioned(s):
    f=s.get("found") or []
    versioned=[x for x in f if any(c.isdigit() for c in x["pattern"]) or "old" in x["pattern"] or "test" in x["pattern"] or "staging" in x["pattern"]]
    if not versioned: return None
    return {"name":f"Old/versioned subdomains exposed ({len(versioned)})","severity":"MEDIUM","cwe":"CWE-1188",
        "evidence":"; ".join(v["subdomain"] for v in versioned[:5]),
        "remediation":"Forgotten old/staging environments often run outdated code. Decommission or restrict access."}
def _r_count(s):
    n=s.get("found_count",0)
    if n==0: return None
    return {"name":f"{n} permutation subdomains live","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join(x["subdomain"] for x in (s.get("found") or [])[:5])}
def _r_clean(s):
    if s.get("found_count",0)>0: return None
    return {"name":"No permutation subdomains resolved","severity":"POSITIVE",
        "evidence":f"Generated + tested {s.get('permutations_generated',0)} patterns"}
FINDING_RULES=[_r_versioned,_r_count,_r_clean]
INTEL_FIELDS=[("Permutations","permutations_generated"),("Found","found_count")]
@router.post("/api/recon/permutation_gen")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="permutation_gen",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found","found_count"])
def register(app): app.include_router(router)
