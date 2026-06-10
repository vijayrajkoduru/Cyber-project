"""GreyNoise v2 — VL-FORGE. Internet-noise classification."""
import asyncio, requests, os
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def gather(ctx):
    key=os.environ.get("GREYNOISE_API_KEY","")
    ips=await _resolve(ctx.host)
    if not ips: return
    ctx.state["ip"]=ips[0]
    # Free community API doesn't need key but has rate limits
    hdr={"key":key} if key else {}
    ctx.state["api_key_configured"]=bool(key)
    try:
        r=await asyncio.to_thread(requests.get,f"https://api.greynoise.io/v3/community/{ips[0]}",
            headers=hdr,timeout=10)
        if r.status_code==200:
            d=r.json()
            ctx.source("greynoise")
            ctx.state.update({"classification":d.get("classification"),
                "noise":d.get("noise"),"riot":d.get("riot"),"name":d.get("name"),
                "last_seen":d.get("last_seen")})
    except: pass
def _r_malicious(s):
    c=s.get("classification","")
    if c!="malicious": return None
    return {"name":"GreyNoise classifies IP as malicious","severity":"CRITICAL","cvss":9.0,
        "cwe":"T1583.003",
        "evidence":f"Tag: {s.get('name','?')} | Last seen: {s.get('last_seen','?')}",
        "remediation":"IP is part of known scanning/attack infrastructure. Investigate immediately."}
def _r_riot(s):
    if not s.get("riot"): return None
    return {"name":f"Known-benign service: {s.get('name','?')}","severity":"POSITIVE",
        "evidence":"GreyNoise RIOT (rule-of-thumb) match — well-known service"}
def _r_noise(s):
    if not s.get("noise"): return None
    return {"name":"IP is internet-noisy (scanned widely)","severity":"INFO",
        "evidence":f"GreyNoise: {s.get('classification','?')}"}
FINDING_RULES=[_r_malicious,_r_riot,_r_noise]
INTEL_FIELDS=[("Classification","classification"),("Noise","noise"),("RIOT","riot"),
    ("Name","name"),("Last seen","last_seen")]
@router.post("/api/recon/greynoise_check")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="greynoise_check",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["classification","name","ip"])
def register(app): app.include_router(router)
