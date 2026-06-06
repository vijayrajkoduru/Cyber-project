"""HTTP Banner v2 — VL-FORGE."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u):
    try:
        return requests.head(u,timeout=8,verify=False,allow_redirects=True,
            headers={"User-Agent":"VulnusLab/1.0"})
    except: return None
async def gather(ctx):
    r=await asyncio.to_thread(_g,web_url(ctx.host))
    if not r: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True
    h={k:v for k,v in r.headers.items()}
    ctx.state["headers"]=h
    ctx.state["server"]=h.get("Server",h.get("server","unknown"))
    ctx.state["powered_by"]=h.get("X-Powered-By",h.get("x-powered-by",""))
    ctx.state["status_code"]=r.status_code
    ctx.source(f"http-{r.status_code}")
def _r_server_version(s):
    srv=s.get("server","")
    if "/" in srv and any(c.isdigit() for c in srv):
        return {"name":f"Server version disclosed: {srv}","severity":"LOW","cwe":"CWE-200",
            "evidence":f"Server: {srv}","remediation":"Hide server tokens"}
def _r_powered_by(s):
    pb=s.get("powered_by","")
    if not pb: return None
    return {"name":f"X-Powered-By: {pb}","severity":"LOW","cwe":"CWE-200","evidence":pb,
        "remediation":"Remove X-Powered-By header"}
def _r_server(s):
    if not s.get("server"): return None
    return {"name":f"Server: {s['server']}","severity":"INFO","evidence":f"Status: {s.get('status_code')}"}
def _r_chain_handoff(s):
    if not s.get("reachable"): return None
    srv=(s.get("server","") or "").lower()
    pb=(s.get("powered_by","") or "").lower()
    h=s.get("headers") or {}
    h_lc={k.lower():(v or "") for k,v in h.items()}
    chain_next=[]; evidence_parts=[]
    if any(x in srv for x in ("apache","nginx","iis","tomcat")):
        for n in ("http_server_cve","appserver_cve"):
            if n not in chain_next: chain_next.append(n)
        evidence_parts.append(f"Server:{srv}")
    if any(x in pb for x in ("php","asp.net","node","express")):
        if "framework_cve" not in chain_next: chain_next.append("framework_cve")
        evidence_parts.append(f"PoweredBy:{pb}")
    if h_lc.get("x-aspnet-version"):
        if "appserver_cve" not in chain_next: chain_next.append("appserver_cve")
        evidence_parts.append(f"AspNetVer:{h_lc.get('x-aspnet-version')}")
    body=(s.get("body","") or "").lower()
    if h_lc.get("x-drupal-cache") or "wp-content" in body:
        for n in ("cms_fingerprint_cve","wp_plugin_brute"):
            if n not in chain_next: chain_next.append(n)
        evidence_parts.append("CMS:drupal/wp")
    waf_markers=("cloudflare","akamai","aws","cf-ray","x-amz-cf-id","x-akamai")
    waf_hit=any(m in (h_lc.get(k,"")).lower() for k in h_lc for m in waf_markers) or \
            any(k in h_lc for k in ("cf-ray","x-amz-cf-id","x-akamai-transformed"))
    if waf_hit or "cloudflare" in srv or "akamai" in srv:
        for n in ("waf_cdn_detect","origin_ip_bypass"):
            if n not in chain_next: chain_next.append(n)
        evidence_parts.append("WAF/CDN")
    cookies=(h_lc.get("set-cookie","") or "").lower()
    if any(c in cookies for c in ("phpsessid","jsessionid","asp.net_sessionid")):
        if "session_predict_audit" not in chain_next: chain_next.append("session_predict_audit")
        evidence_parts.append("SessionCookie")
    if any(m in body for m in ("/admin","/wp-admin","login","sign in")):
        if "patator_http_form_brute" not in chain_next: chain_next.append("patator_http_form_brute")
        evidence_parts.append("AdminLogin")
    if not chain_next: return None
    return {
        "name":"Cross-module chain handoff - HTTP banner identifies follow-up scanners",
        "severity":"INFO",
        "evidence":f"Server/PoweredBy: {'; '.join(evidence_parts)}; suggests {len(chain_next)} follow-up scanner(s)",
        "remediation":"Each detected server/framework has known CVEs and config issues. Suppress version banners (server_tokens off) + run CVE-lookup scanners.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"http_banner_to_cve_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_server_version,_r_powered_by,_r_server,_r_chain_handoff]
INTEL_FIELDS=[("Server","server"),("X-Powered-By","powered_by"),("Status","status_code")]
@router.post("/api/recon/http_banner")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="http_banner",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["server","powered_by","status_code","headers"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "http_banner", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("http_banner", _chain_callable)
