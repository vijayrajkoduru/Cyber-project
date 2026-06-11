"""HSTS Audit v2 — VL-FORGE. Strict-Transport-Security policy check."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
def _g(u):
    try: return requests.get(u,timeout=8,verify=False,allow_redirects=False,headers={"User-Agent":"VulnusLab/1.0"})
    except Exception: return None
async def gather(ctx):
    https_r=await asyncio.to_thread(_g,f"https://{ctx.host}/")
    http_r=await asyncio.to_thread(_g,f"http://{ctx.host}/")
    if not https_r: ctx.state["https_reachable"]=False; return
    ctx.state["https_reachable"]=True
    hsts=https_r.headers.get("Strict-Transport-Security",https_r.headers.get("strict-transport-security",""))
    ctx.state["hsts_header"]=hsts
    ctx.source("https")
    # Parse HSTS
    max_age=0; include_subs=False; preload=False
    if hsts:
        for part in hsts.split(";"):
            p=part.strip().lower()
            if p.startswith("max-age="):
                try: max_age=int(p.split("=")[1])
                except Exception: pass
            elif "includesubdomains" in p: include_subs=True
            elif "preload" in p: preload=True
    ctx.state.update({"max_age":max_age,"include_subdomains":include_subs,"preload":preload,
        "http_redirects":http_r and http_r.status_code in (301,302,307,308) if http_r else None})
def _r_no_hsts(s):
    if s.get("hsts_header") or not s.get("https_reachable"): return None
    return {"name":"No HSTS header","severity":"HIGH","cvss":7.0,"cwe":"CWE-319",
        "owasp":"A02:2021","evidence":"Missing Strict-Transport-Security",
        "remediation":"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"}
def _r_short_max_age(s):
    ma=s.get("max_age",0)
    if not s.get("hsts_header") or ma>=31536000: return None
    return {"name":f"HSTS max-age too short ({ma}s)","severity":"MEDIUM","cwe":"CWE-326",
        "evidence":f"max-age={ma}, recommended >= 31536000 (1 year)",
        "remediation":"Increase max-age to 31536000 (1 year)."}
def _r_no_subs(s):
    if not s.get("hsts_header") or s.get("include_subdomains"): return None
    return {"name":"HSTS missing includeSubDomains","severity":"LOW","cwe":"CWE-319",
        "evidence":s.get("hsts_header"),"remediation":"Add includeSubDomains directive"}
def _r_preload(s):
    if not s.get("preload"): return None
    return {"name":"HSTS preload enabled","severity":"POSITIVE","evidence":s.get("hsts_header")}
def _r_no_http_redirect(s):
    hr=s.get("http_redirects")
    if hr is None or hr: return None
    return {"name":"HTTP doesn't redirect to HTTPS","severity":"MEDIUM","cwe":"CWE-319",
        "evidence":"Port 80 serves content without redirect",
        "remediation":"Enforce HTTPS via 301 redirect from port 80."}
FINDING_RULES=[_r_no_hsts,_r_short_max_age,_r_no_subs,_r_preload,_r_no_http_redirect]
INTEL_FIELDS=[("HSTS","hsts_header"),("Max-age","max_age"),
    ("includeSubDomains","include_subdomains"),("preload","preload"),("HTTP→HTTPS redirect","http_redirects")]
@router.post("/api/recon/hsts_audit")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="hsts_audit",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["hsts_header","max_age","preload"])
def register(app): app.include_router(router)
