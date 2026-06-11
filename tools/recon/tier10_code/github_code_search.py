"""github_code_search v2 — VL-FORGE."""
import asyncio, os, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def gather(ctx):
    tok=os.environ.get("GITHUB_TOKEN","")
    ctx.state["api_key_configured"]=bool(tok)
    if not tok: return
    try:
        r=await asyncio.to_thread(requests.get,
            f"https://api.github.com/search/code?q=%22{ctx.host}%22&per_page=20",
            headers={"Authorization":f"Bearer {tok}","Accept":"application/vnd.github+json"},timeout=15)
        if r.status_code==200:
            d=r.json(); ctx.source("github-code")
            ctx.state["matches"]=d.get("total_count",0)
            ctx.state["repos"]=[i.get("repository",{}).get("full_name") for i in d.get("items",[])][:10]
    except: pass
def _r_leaked(s):
    n=s.get("matches",0)
    if n==0: return None
    return {"name":f"Domain in {n} public GitHub files","severity":"MEDIUM","cwe":"CWE-540",
        "evidence":"Repos: "+", ".join((s.get("repos") or [])[:5]),
        "remediation":"Audit each repo for hardcoded credentials."}
def _r_no_key(s):
    if s.get("api_key_configured"): return None
    return {"name":"GITHUB_TOKEN not set","severity":"INFO","evidence":"Required"}
FINDING_RULES=[_r_leaked,_r_no_key]
INTEL_FIELDS=[("API key","api_key_configured"),("Matches","matches")]
@router.post("/api/recon/github_code_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="github_code_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
