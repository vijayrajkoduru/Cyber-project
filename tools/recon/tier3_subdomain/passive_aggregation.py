"""Passive Aggregation v2 — VL-FORGE. Merge passive sources."""
import asyncio, requests, json
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
async def gather(ctx):
    h=ctx.host
    crt,hackertarget,bufferover=await asyncio.gather(
        asyncio.to_thread(_g,f"https://crt.sh/?q=%25.{h}&output=json"),
        asyncio.to_thread(_g,f"https://api.hackertarget.com/hostsearch/?q={h}"),
        asyncio.to_thread(_g,f"https://dns.bufferover.run/dns?q=.{h}"))
    subs=set()
    if crt:
        ctx.source("crt.sh")
        try:
            for e in json.loads(crt)[:300]:
                for n in (e.get("name_value","") or "").split("\n"):
                    n=n.strip().lower()
                    if n.endswith(h) and "*" not in n and n!=h: subs.add(n)
        except: pass
    if hackertarget:
        ctx.source("hackertarget")
        for line in hackertarget.splitlines():
            host=line.split(",")[0].strip().lower()
            if host.endswith(h) and host!=h: subs.add(host)
    if bufferover:
        ctx.source("bufferover")
        try:
            d=json.loads(bufferover)
            for entry in (d.get("FDNS_A") or []) + (d.get("RDNS") or []):
                parts=entry.split(",")
                if len(parts)>=2:
                    host=parts[-1].strip().lower()
                    if host.endswith(h) and host!=h: subs.add(host)
        except: pass
    ctx.state.update({"subdomains":sorted(subs)[:100],"count":len(subs),
        "sources_count":sum(1 for x in [crt,hackertarget,bufferover] if x)})
def _r_many(s):
    n=s.get("count",0)
    if n==0: return None
    sev="INFO" if n<20 else ("LOW" if n<100 else "MEDIUM")
    return {"name":f"{n} subdomains from passive aggregation","severity":sev,"cwe":"T1596.001",
        "evidence":f"Sources: {s.get('sources_count',0)}/3 (crt.sh + hackertarget + bufferover)",
        "remediation":"Passive sources are public — assume all subdomains known to attackers."}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains in passive sources","severity":"POSITIVE",
        "evidence":"crt.sh + hackertarget + bufferover all empty"}
FINDING_RULES=[_r_many,_r_clean]
INTEL_FIELDS=[("Subdomains","count"),("Sources","sources_count")]
@router.post("/api/recon/passive_aggregation")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="passive_aggregation",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
