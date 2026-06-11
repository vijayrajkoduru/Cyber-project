"""Wayback Subdomain Extract v2 — VL-FORGE. Mine Wayback for subdomains."""
import asyncio, requests, json, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u,t=20):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except Exception: pass
    return None
async def gather(ctx):
    h=ctx.host
    txt=await asyncio.to_thread(_g,
        f"http://web.archive.org/cdx/search/cdx?url=*.{h}/*&output=json&fl=original&collapse=urlkey&limit=10000")
    subs=set()
    if txt:
        ctx.source("wayback-cdx")
        try:
            data=json.loads(txt)
            pat=re.compile(rf"https?://([\w\-]+\.{re.escape(h)})",re.I)
            for row in data[1:]:
                if row and len(row)>=1:
                    for m in pat.findall(row[0]):
                        subs.add(m.lower())
        except Exception: pass
    ctx.state.update({"subdomains":sorted(subs)[:100],"count":len(subs)})
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains in Wayback archive","severity":"INFO","cwe":"T1596",
        "evidence":"Sample: "+", ".join((s.get("subdomains") or [])[:5]),
        "remediation":"Historic subdomains may still resolve. Probe to find live ones."}
def _r_clean(s):
    if s.get("count",0)>0: return None
    return {"name":"No subdomains in Wayback","severity":"POSITIVE","evidence":"CDX returned 0"}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Subdomains","count")]
@router.post("/api/recon/wayback_subdomain_extract")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="wayback_subdomain_extract",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
