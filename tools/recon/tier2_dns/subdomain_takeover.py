"""Subdomain Takeover v2 — VL-FORGE. Dangling CNAME + service fingerprint."""
import asyncio, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_TAKEOVER_SIGS={
    "github.io":"There isn't a GitHub Pages site here",
    "herokuapp.com":"No such app",
    "amazonaws.com":"NoSuchBucket",
    "azurewebsites.net":"404 Web Site not found",
    "cloudfront.net":"ERROR: The request could not be satisfied",
    "fastly.net":"Fastly error: unknown domain",
    "ghost.io":"The thing you were looking for is no longer here",
    "shopify.com":"Sorry, this shop is currently unavailable",
    "tumblr.com":"Whatever you were looking for doesn't currently exist",
    "wordpress.com":"Do you want to register",
    "wpengine.com":"The site you were looking for couldn't be found",
    "zendesk.com":"this help center no longer exists",
    "netlify.app":"Not Found - Request ID",
    "vercel.app":"DEPLOYMENT_NOT_FOUND",
}
async def _resolve_cname(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,"CNAME")]
    except: return []
def _check(url,sig):
    try:
        r=requests.get(url,timeout=8,verify=False,headers={"User-Agent":"VulnusLab/1.0"})
        return sig in (r.text or "")[:8192]
    except: return False
async def gather(ctx):
    cname=await _resolve_cname(ctx.host)
    if not cname: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["cname"]=cname
    ctx.source(f"cname-{cname[0]}")
    # Check each CNAME for takeover potential
    vulnerable=[]
    for c in cname:
        for service,sig in _TAKEOVER_SIGS.items():
            if service in c.lower():
                # Try HTTP fetch on apex
                http_url=f"http://{ctx.host}/"
                https_url=f"https://{ctx.host}/"
                ctx.source(f"probe-{service}")
                found_sig=await asyncio.to_thread(_check,http_url,sig) or \
                          await asyncio.to_thread(_check,https_url,sig)
                if found_sig:
                    vulnerable.append({"cname":c,"service":service,"signature":sig})
                else:
                    ctx.state.setdefault("checked_services",[]).append(service)
                break
    ctx.state["vulnerable_takeover"]=vulnerable
def _r_takeover(s):
    v=s.get("vulnerable_takeover") or []
    if not v: return None
    return {"name":f"Subdomain takeover possible ({len(v)})","severity":"CRITICAL","cvss":9.0,
        "cwe":"CWE-350","owasp":"A05:2021",
        "evidence":f"Dangling CNAME: {v[0]['cname']} → {v[0]['service']}",
        "remediation":"Remove the dangling CNAME OR re-register the {v[0]['service']} resource. CRITICAL — attacker can claim it."}
def _r_cname(s):
    c=s.get("cname") or []
    if not c: return None
    if s.get("vulnerable_takeover"): return None
    return {"name":f"CNAME chain: {c[0]}","severity":"INFO",
        "evidence":"No takeover signature matched"}
def _r_no_cname(s):
    if s.get("reachable"): return None
    return {"name":"No CNAME (not vulnerable to takeover via dangling CNAME)","severity":"POSITIVE",
        "evidence":"Direct A record, no CNAME indirection"}
FINDING_RULES=[_r_takeover,_r_cname,_r_no_cname]
INTEL_FIELDS=[("CNAME","cname"),("Vulnerable","vulnerable_takeover")]
@router.post("/api/recon/subdomain_takeover")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="subdomain_takeover",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["cname","vulnerable_takeover"])
def register(app): app.include_router(router)
