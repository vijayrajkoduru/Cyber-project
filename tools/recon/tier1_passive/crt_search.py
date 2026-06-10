"""crt.sh search v2 — VL-FORGE. CT log certificate discovery."""
import asyncio, requests, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
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
    wildcard_count=0; san_total=0; ev_ov_orgs=set(); sha1_seen=False
    for txt in [t1,t2]:
        if not txt: continue
        try: data=json.loads(txt)
        except: continue
        ctx.source("crt.sh")
        for e in data[:500]:
            nv=(e.get("name_value","") or "").strip()
            names_in_cert=[n.strip().lower() for n in nv.split("\n") if n.strip()]
            san_total+=len(names_in_cert)
            for n in names_in_cert:
                if n.startswith("*."): wildcard_count+=1
                if n.endswith(host) and "*" not in n and n != host: subs.add(n)
            issuer=(e.get("issuer_name","") or "").split(",")[0]
            if issuer: issuers[issuer]=issuers.get(issuer,0)+1
            # EV/OV detection: issuer_name often has "O=" org field for OV/EV certs
            issuer_full=(e.get("issuer_name","") or "")
            for part in issuer_full.split(","):
                part=part.strip()
                if part.startswith("O=") and len(part)>3:
                    org=part[2:].strip().strip('"')
                    if org and org.lower() not in ("let's encrypt","lets encrypt"):
                        ev_ov_orgs.add(org[:80])
            # SHA-1 detection (legacy field signature_algorithm if present)
            sig=(e.get("signature_algorithm","") or "").lower()
            if "sha1" in sig: sha1_seen=True
            d=e.get("not_before","")
            if d: recent_certs.append({"name":nv[:60],"issuer":issuer[:60],"not_before":d})
    ctx.state["subdomains"]=sorted(subs)[:50]
    ctx.state["subdomain_count"]=len(subs)
    ctx.state["issuers"]=dict(sorted(issuers.items(),key=lambda x:-x[1])[:5])
    ctx.state["recent_certs_count"]=len(recent_certs)
    ctx.state["wildcard_count"]=wildcard_count
    ctx.state["san_total"]=san_total
    ctx.state["ev_ov_orgs"]=sorted(ev_ov_orgs)[:5]
    ctx.state["sha1_seen"]=sha1_seen
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
