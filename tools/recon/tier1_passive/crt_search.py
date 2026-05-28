"""crt.sh search v2 — VL-FORGE. CT log certificate discovery."""
import asyncio, requests, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=15):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    host=ctx.host
    t1,t2=await asyncio.gather(
        asyncio.to_thread(_g,f"https://crt.sh/?q=%25.{host}&output=json"),
        asyncio.to_thread(_g,f"https://crt.sh/?q={host}&output=json"))
    subs=set(); issuers={}; recent_certs=[]
    for txt in [t1,t2]:
        if not txt: continue
        try: data=json.loads(txt)
        except: continue
        ctx.source("crt.sh")
        for e in data[:500]:
            nv=(e.get("name_value","") or "").strip()
            for n in nv.split("\n"):
                n=n.strip().lower()
                if n.endswith(host) and "*" not in n and n != host: subs.add(n)
            issuer=(e.get("issuer_name","") or "").split(",")[0]
            if issuer: issuers[issuer]=issuers.get(issuer,0)+1
            d=e.get("not_before","")
            if d: recent_certs.append({"name":nv[:60],"issuer":issuer[:60],"not_before":d})
    ctx.state["subdomains"]=sorted(subs)[:50]
    ctx.state["subdomain_count"]=len(subs)
    ctx.state["issuers"]=dict(sorted(issuers.items(),key=lambda x:-x[1])[:5])
    ctx.state["recent_certs_count"]=len(recent_certs)
    ctx.state["reachable"]=bool(subs or recent_certs)
def _r_subs(s):
    n=s.get("subdomain_count") or 0
    if n==0: return None
    sev="INFO" if n<20 else ("LOW" if n<100 else "MEDIUM")
    return {"name":f"{n} subdomains via CT logs","severity":sev,"cwe":"T1596.001",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5]),
        "remediation":"CT logs are public — assume all subdomains discoverable."}
def _r_issuer(s):
    iss=s.get("issuers") or {}
    if not iss: return None
    primary=list(iss.keys())[0]
    return {"name":f"Primary cert issuer: {primary}","severity":"INFO",
        "evidence":f"Top 5: {dict(list(iss.items())[:5])}"}
def _r_clean(s):
    if (s.get("subdomain_count") or 0)>0: return None
    if not s.get("reachable"): return None
    return {"name":"No subdomains in CT logs","severity":"POSITIVE",
        "evidence":"Limited cert history — narrow public footprint"}
FINDING_RULES=[_r_subs,_r_issuer,_r_clean]
INTEL_FIELDS=[("Subdomain count","subdomain_count"),("Cert issuers","issuers"),
    ("Recent certs","recent_certs_count")]
@router.post("/api/recon/crt_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="crt_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","subdomain_count","issuers"])
def register(app): app.include_router(router)
