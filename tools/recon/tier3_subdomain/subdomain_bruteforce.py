"""Subdomain Brute v2 — VL-FORGE. Concurrent DNS brute."""
import asyncio
from pathlib import Path
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
_PAYLOAD=Path(__file__).resolve().parent.parent.parent/"_payloads"/"recon"/"ai_subs.txt"
_TOP=["www","mail","ftp","admin","api","dev","test","staging","portal","vpn","cdn","static","app","blog","shop","secure","support","help","docs","status"]
async def _q(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=3;r.lifetime=4
        ans=await r.resolve(h,"A")
        return [str(x).rstrip(".") for x in ans]
    except: return []
def _load(cap=300):
    try:
        if _PAYLOAD.exists():
            return [l.strip().lower() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")][:cap]
    except: pass
    return _TOP
async def gather(ctx):
    words=_load()
    ctx.state["wordlist_size"]=len(words)
    ctx.source(f"wordlist-{len(words)}")
    sem=asyncio.Semaphore(40)
    async def one(w):
        async with sem:
            sub=f"{w}.{ctx.host}"
            ips=await _q(sub)
            return (sub,ips) if ips else None
    results=await asyncio.gather(*[one(w) for w in words])
    found=[{"subdomain":s,"ips":i} for r in results if r for s,i in [r]]
    ctx.state["subdomains_found"]=found
    ctx.state["count"]=len(found)
    if found: ctx.source(f"resolved-{len(found)}")
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    sev="INFO" if n<10 else ("LOW" if n<30 else "MEDIUM")
    return {"name":f"{n} subdomains via brute-force","severity":sev,"cwe":"T1596.001",
        "evidence":"Sample: "+", ".join([f["subdomain"] for f in (s.get("subdomains_found") or [])][:5])}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains found via brute-force","severity":"POSITIVE",
        "evidence":f"Probed {s.get('wordlist_size',0)} candidates"}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Wordlist size","wordlist_size"),("Subdomains","count"),("Found","subdomains_found")]
@router.post("/api/recon/subdomain_bruteforce")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="subdomain_bruteforce",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains_found","count"])
def register(app): app.include_router(router)
