"""GitHub Org Recon v2 — VL-FORGE. Find org repos + members."""
import asyncio, requests, os
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._targeting import get_org_name, can_do_osint
router=APIRouter()
_GENERIC_ORG_NAMES = frozenset({
    "app","api","www","web","dev","staging","test","demo","admin",
    "portal","site","shop","blog","mail","cdn","static","assets",
})
def _g(u,h=None):
    try:
        r=requests.get(u,timeout=12,headers={"User-Agent":"VulnusLab/1.0",**(h or {})})
        if r.status_code==200: return r.json()
    except: pass
    return None
async def gather(ctx):
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="OSINT not applicable for IP / internal hostname"
        return
    org = get_org_name(ctx.host)
    if not org or org.lower() in _GENERIC_ORG_NAMES or len(org) < 4:
        ctx.state["skipped_reason"]=f"Org name '{org}' too generic to search GitHub without massive false-positive risk"
        return
    ctx.state["org_guess"]=org
    tok=os.environ.get("GITHUB_TOKEN","")
    hdr={"Authorization":f"Bearer {tok}"} if tok else {}
    ctx.state["github_token_set"]=bool(tok)
    # Check org exists
    org_data=await asyncio.to_thread(_g,f"https://api.github.com/orgs/{org}",hdr)
    if not org_data: ctx.state["org_found"]=False; return
    ctx.state["org_found"]=True
    ctx.source(f"org-{org}")
    ctx.state.update({"org_name":org_data.get("login"),"description":org_data.get("description",""),
        "public_repos":org_data.get("public_repos",0),"public_members":org_data.get("public_members",0),
        "blog":org_data.get("blog",""),"location":org_data.get("location","")})
    # Repos + members
    repos,members=await asyncio.gather(
        asyncio.to_thread(_g,f"https://api.github.com/orgs/{org}/repos?per_page=50",hdr),
        asyncio.to_thread(_g,f"https://api.github.com/orgs/{org}/members?per_page=50",hdr))
    if repos:
        ctx.source(f"repos-{len(repos)}")
        ctx.state["repos"]=[{"name":r.get("name"),"language":r.get("language"),
            "stars":r.get("stargazers_count",0),"updated":r.get("updated_at","")} for r in repos[:20]]
    if members:
        ctx.source(f"members-{len(members)}")
        ctx.state["members"]=[m.get("login") for m in members[:30]]
def _r_org(s):
    if not s.get("org_found"): return None
    return {"name":f"GitHub org '{s.get('org_name')}' confirmed","severity":"INFO","cwe":"T1593.003",
        "evidence":f"{s.get('public_repos',0)} repos, {s.get('public_members',0)} members"}
def _r_many_repos(s):
    n=s.get("public_repos",0)
    if n<20: return None
    return {"name":f"Large GitHub footprint ({n} public repos)","severity":"LOW","cwe":"CWE-200",
        "evidence":"Each repo = potential secret leak surface",
        "remediation":"Audit each repo with secret_pattern_scanner. Configure GitHub secret scanning."}
def _r_no_org(s):
    if s.get("org_found"): return None
    return {"name":"No GitHub org matching domain prefix","severity":"INFO",
        "evidence":f"Tried org name '{s.get('org_guess')}'"}
FINDING_RULES=[_r_org,_r_many_repos,_r_no_org]
INTEL_FIELDS=[("Org found","org_found"),("Org name","org_name"),("Public repos","public_repos"),
    ("Public members","public_members"),("Location","location"),("Blog","blog")]
@router.post("/api/recon/github_org_recon")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="github_org_recon",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["repos","members","org_name","public_repos"])
def register(app): app.include_router(router)
