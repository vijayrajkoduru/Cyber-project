"""Wayback Subdomain Extract v2 — VL-FORGE. Mine Wayback for subdomains."""
import asyncio, requests, json, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=20):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"VulnusLab/1.0"})
        if r.status_code==200: return r.text
    except: pass
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
        except: pass
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
def _r_chain_handoff(s):
    subs=s.get("subdomains") or []
    n=s.get("count",0)
    if n==0: return None
    chain_next=[]
    # Historical subdomains found -> takeover + port scan + tech stack
    for sc in ("subdomain_takeover","tcp_port_scan","tech_stack_detect"):
        if sc not in chain_next: chain_next.append(sc)
    sub_blob=" ".join(subs).lower()
    # Wayback shows admin/dev paths
    if any(k in sub_blob for k in ("admin","dev","staging","test","internal","qa")):
        for sc in ("exposed_env_scan","patator_http_form_brute"):
            if sc not in chain_next: chain_next.append(sc)
    # Wayback shows old paths -> may still be reachable
    for sc in ("exposed_env_scan","git_secrets_scan"):
        if sc not in chain_next: chain_next.append(sc)
    # Wayback reveals API endpoints
    if any(k in sub_blob for k in ("api","graphql","rest","swagger","v1","v2")):
        for sc in ("api_endpoint_brute","swagger_openapi_discovery"):
            if sc not in chain_next: chain_next.append(sc)
    # Old subdomain on cloud provider
    if any(k in sub_blob for k in ("s3","aws","cloudfront","blob","azure","storage","gcs","cdn")):
        if "s3_bucket_enum" not in chain_next: chain_next.append("s3_bucket_enum")
    if not chain_next: return None
    return {
        "name":"Cross-module chain handoff - historical Wayback subdomains for follow-up",
        "severity":"INFO",
        "evidence":f"Wayback shows {n} historical subdomain(s); suggests {len(chain_next)} follow-up scanner(s)",
        "remediation":"Historical subdomains often forgotten-but-still-reachable. Takeover + port scan + env scan each.",
        "cwe":"CWE-1006",
        "chain_next":chain_next,
        "discovery_method":"wayback_to_forgotten_asset_chain",
        "source_stage":"chain_handoff",
        "confidence":"INFO",
    }
FINDING_RULES=[_r_found,_r_clean,_r_chain_handoff]
INTEL_FIELDS=[("Subdomains","count")]
@router.post("/api/recon/wayback_subdomain_extract")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="wayback_subdomain_extract",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "wayback_subdomain_extract", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("wayback_subdomain_extract", _chain_callable)
