"""Shodan Keyed v2 — VL-FORGE. Host intel + CVE matching via Shodan API."""
import asyncio, requests, os
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def gather(ctx):
    key=os.environ.get("SHODAN_API_KEY","")
    ctx.state["api_key_configured"]=bool(key)
    if not key: return
    ips=await _resolve(ctx.host)
    if not ips: return
    ctx.state["ips"]=ips
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.shodan.io/shodan/host/{ips[0]}?key={key}",timeout=15)
        if r.status_code==200:
            d=r.json()
            ctx.source("shodan-host")
            ctx.state.update({"ports":d.get("ports") or [],
                "vulns":list(d.get("vulns") or []),
                "tags":d.get("tags") or [],
                "hostnames":d.get("hostnames") or [],
                "country":d.get("country_name"),"isp":d.get("isp"),
                "os":d.get("os"),"org":d.get("org")})
        elif r.status_code==401: ctx.state["auth_error"]=True
        elif r.status_code==404: ctx.state["not_in_shodan"]=True
    except: pass
def _r_vulns(s):
    v=s.get("vulns") or []
    if not v: return None
    return {"name":f"Shodan-known vulnerabilities ({len(v)})","severity":"HIGH","cvss":7.5,
        "cwe":"CWE-1395","owasp":"A06:2021",
        "evidence":f"CVEs: {', '.join(v[:5])}",
        "remediation":"Patch each CVE. Verify Shodan's attribution by checking actual service versions."}
def _r_ports(s):
    p=s.get("ports") or []
    if not p: return None
    return {"name":f"{len(p)} ports indexed by Shodan","severity":"INFO",
        "evidence":f"Ports: {p[:15]}"}
def _r_org(s):
    if not s.get("org"): return None
    return {"name":f"Hosting org: {s['org']}","severity":"INFO",
        "evidence":f"Country: {s.get('country','?')} | ISP: {s.get('isp','?')}"}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"SHODAN_API_KEY not set","severity":"INFO","evidence":"Free $59 lifetime key at shodan.io"}
FINDING_RULES=[_r_vulns,_r_ports,_r_org,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Ports","ports"),("Vulns","vulns"),
    ("OS","os"),("Org","org"),("Country","country"),("Tags","tags")]
@router.post("/api/recon/shodan_keyed")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="shodan_keyed",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["ports","vulns","org","country","tags"])
def register(app): app.include_router(router)
