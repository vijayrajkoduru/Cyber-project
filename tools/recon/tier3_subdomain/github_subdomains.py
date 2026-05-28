"""GitHub Subdomains v2 — VL-FORGE. Code search for *.target leaks."""
import asyncio, requests, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
async def gather(ctx):
    token=os.environ.get("GITHUB_TOKEN","")
    if not token: ctx.state["api_key_configured"]=False; return
    ctx.state["api_key_configured"]=True
    h=ctx.host
    try:
        r=requests.get(f"https://api.github.com/search/code?q=%22.{h}%22&per_page=50",
            headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json"},timeout=15)
        if r.status_code==200:
            d=r.json()
            subs=set()
            pat=re.compile(rf"[\w\-]+\.{re.escape(h)}",re.I)
            for item in d.get("items",[]):
                # We don't fetch content; rely on text snippets in response
                tm=item.get("text_matches",[]) or []
                for m in tm:
                    for hit in pat.findall(m.get("fragment","") or ""):
                        subs.add(hit.lower())
            ctx.state["subdomains"]=sorted(subs)[:100]; ctx.state["count"]=len(subs)
            ctx.state["repos_matched"]=d.get("total_count",0)
            ctx.source(f"github-{ctx.state['count']}")
        elif r.status_code==401: ctx.state["auth_error"]=True
        elif r.status_code==403: ctx.state["rate_limited"]=True
    except: pass
def _r_unkeyed(s):
    if s.get("api_key_configured"): return None
    return {"name":"GITHUB_TOKEN not configured","severity":"INFO",
        "evidence":"Enable for GitHub code search subdomain discovery"}
def _r_found(s):
    n=s.get("count",0)
    if n==0: return None
    return {"name":f"{n} subdomains leaked in GitHub code","severity":"MEDIUM","cwe":"CWE-540",
        "evidence":f"Found across {s.get('repos_matched',0)} repos. Sample: "+", ".join((s.get('subdomains') or [])[:5]),
        "remediation":"Hostnames in public code = recon goldmine. Audit repos for hardcoded internal hosts."}
def _r_clean(s):
    if s.get("count",0)>0 or not s.get("api_key_configured"): return None
    return {"name":"No subdomains leaked in GitHub","severity":"POSITIVE",
        "evidence":"Code search returned 0 matches"}
FINDING_RULES=[_r_unkeyed,_r_found,_r_clean]
INTEL_FIELDS=[("API key","api_key_configured"),("Subdomains","count"),("Repos","repos_matched")]
@router.post("/api/recon/github_subdomains")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="github_subdomains",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains","count"])
def register(app): app.include_router(router)
