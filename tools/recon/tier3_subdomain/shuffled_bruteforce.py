"""Shuffled Bruteforce v2 — VL-FORGE. Shuffled DNS brute (anti rate-limit)."""
import asyncio, random
from pathlib import Path
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_PAYLOAD=Path(__file__).resolve().parent.parent.parent/"_payloads"/"recon"/"ai_subs.txt"
_FB=["api","admin","app","beta","corp","dev","docs","grafana","internal","jenkins","kibana","mail","portal","staging","status","support","test","vpn","www"]
_RESOLVERS=["1.1.1.1","8.8.8.8","9.9.9.9","208.67.222.222"]
async def _q(h,resolver):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=3;r.lifetime=4
        r.nameservers=[resolver]
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _load(cap=500):
    try:
        if _PAYLOAD.exists():
            l=[x.strip().lower() for x in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                if x.strip() and not x.startswith("#")]
            random.shuffle(l)
            return l[:cap]
    except: pass
    return _FB
async def gather(ctx):
    words=_load()
    ctx.state["wordlist_size"]=len(words)
    ctx.source(f"shuffled-{len(words)}")
    sem=asyncio.Semaphore(30)
    async def one(w,resolver):
        async with sem:
            sub=f"{w}.{ctx.host}"
            ips=await _q(sub,resolver)
            return {"subdomain":sub,"ips":ips,"resolver":resolver} if ips else None
    tasks=[one(w,random.choice(_RESOLVERS)) for w in words]
    res=await asyncio.gather(*tasks)
    found=[r for r in res if r]
    ctx.state["found"]=found; ctx.state["count"]=len(found)
    if found: ctx.source(f"resolved-{len(found)}")
def _r_count(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains (rotated-resolver brute)","severity":"INFO","cwe":"T1596.001",
        "evidence":"Sample: "+", ".join([f["subdomain"] for f in (s.get("found") or [])][:5])}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains via shuffled brute","severity":"POSITIVE",
        "evidence":f"Probed {s.get('wordlist_size',0)} candidates across 4 resolvers"}
FINDING_RULES=[_r_count,_r_clean]
INTEL_FIELDS=[("Wordlist size","wordlist_size"),("Subdomains","count")]
@router.post("/api/recon/shuffled_bruteforce")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="shuffled_bruteforce",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["found","count"])
def register(app): app.include_router(router)
