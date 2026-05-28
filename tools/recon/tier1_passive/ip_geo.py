"""IP Geo v2 — VL-FORGE. Multi-source geolocation (ip-api.com + ipapi.co)."""
import asyncio, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u):
    try:
        r=requests.get(u,timeout=8,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.json()
    except: pass
    return None
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver(); r.timeout=4; r.lifetime=6
        a=await r.resolve(h,"A")
        return [str(x).rstrip(".") for x in a]
    except: return []
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ips"]=ips
    ctx.source(f"dns-{len(ips)}")
    ip=ips[0]
    a,b=await asyncio.gather(
        asyncio.to_thread(_g,f"http://ip-api.com/json/{ip}"),
        asyncio.to_thread(_g,f"https://ipapi.co/{ip}/json/"))
    if a: ctx.source("ip-api.com")
    if b: ctx.source("ipapi.co")
    # Reconcile: prefer ip-api, fallback ipapi
    country=(a or {}).get("country") or (b or {}).get("country_name")
    city=(a or {}).get("city") or (b or {}).get("city")
    region=(a or {}).get("regionName") or (b or {}).get("region")
    isp=(a or {}).get("isp") or (b or {}).get("org")
    asn=(a or {}).get("as") or (b or {}).get("asn")
    consistent=country==(b or {}).get("country_name") if (a and b) else None
    ctx.state.update({"country":country,"city":city,"region":region,"isp":isp,
        "asn_string":asn,"sources_count":sum(1 for x in [a,b] if x),
        "geo_consistent":consistent})
def _r_geo(s):
    if not s.get("country"): return None
    return {"name":f"IP geolocation: {s['city']}, {s.get('region')}, {s['country']}",
        "severity":"INFO","evidence":f"ISP: {s.get('isp','?')}"}
def _r_inconsistent(s):
    c=s.get("geo_consistent")
    if c is None or c: return None
    return {"name":"IP geo sources disagree on country","severity":"LOW","cwe":"CWE-345",
        "evidence":"ip-api vs ipapi.co returned different countries — investigate"}
def _r_consistent(s):
    if not s.get("geo_consistent"): return None
    return {"name":"Geo data consistent across 2 sources","severity":"POSITIVE",
        "evidence":"ip-api + ipapi.co agreed"}
def _r_un(s):
    if s.get("reachable"): return None
    return {"name":"IP geo unavailable","severity":"INFO","evidence":"DNS resolve failed"}
FINDING_RULES=[_r_geo,_r_inconsistent,_r_consistent,_r_un]
INTEL_FIELDS=[("Reachable","reachable"),("IPs","ips"),("Country","country"),
    ("City","city"),("Region","region"),("ISP","isp"),("ASN string","asn_string"),
    ("Sources","sources_count")]
@router.post("/api/recon/ip_geo")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ip_geo",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["ips","country","city","isp"])
def register(app): app.include_router(router)
