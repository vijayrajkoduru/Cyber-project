"""docker_hub_search — VL-FORGE. Own-code, no key: search Docker Hub for org public images."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.recon._targeting import get_org_name, can_do_osint
router=APIRouter()
# Generic words that produce massive FP fan-out when used as the org name.
# If the extracted org is in this list, the scanner SKIPS rather than
# returning thousands of unrelated images. Customer can manually supply a
# real org name via a future intake field if they want.
_GENERIC_ORG_NAMES = frozenset({
    "app", "api", "www", "web", "dev", "staging", "test", "demo", "admin",
    "portal", "site", "shop", "blog", "mail", "cdn", "static", "assets",
    "io", "co", "ai", "me", "org", "net", "com",
})
def _search(term):
    try:
        r=requests.get("https://hub.docker.com/v2/search/repositories/",
            params={"query":term,"page_size":25}, timeout=8, headers={"User-Agent":"VulnusLab/1.0"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    # ZERO-FP-V1: use apex-extracted org, not the subdomain. Skip if target
    # has no real-world brand (IP, internal hostname).
    if not can_do_osint(ctx.host):
        ctx.state["skipped_reason"]="OSINT not applicable for IP / internal hostname"
        return
    org = get_org_name(ctx.host)
    if not org or org.lower() in _GENERIC_ORG_NAMES or len(org) < 4:
        ctx.state["skipped_reason"]=f"Org name '{org}' too generic to search Docker Hub without massive false-positive risk"
        return
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("dockerhub")
    # Match must be STRICT: image namespace or name must equal/begin with org.
    # Substring matching (old) reported 'istio/app' as a vulnuslab hit because
    # 'app' appeared anywhere in the repo name.
    hits=[]
    for x in (j.get("results") or []):
        name = str(x.get("repo_name") or x.get("name") or "").lower()
        namespace = name.split("/",1)[0] if "/" in name else name
        if namespace == org.lower() or namespace.startswith(org.lower() + "-") or namespace.startswith(org.lower() + "_"):
            hits.append({"name": x.get("repo_name") or x.get("name"), "stars": x.get("star_count", 0)})
    ctx.state.update({"org":org,"images":hits,"image_count":len(hits)})
def _r_found(s):
    im=s.get("images") or []
    if not im: return None
    return {"name":"%d public Docker Hub image(s) match org name"%len(im),"severity":"INFO","cwe":"CWE-200",
        "evidence":", ".join(i["name"] for i in im[:6]),
        "remediation":"Confirm these are intended public; secrets/source in public images is a common leak."}
def _r_clean(s):
    if not s.get("reachable") or s.get("images"): return None
    return {"name":"No org-matched public Docker Hub images","severity":"POSITIVE",
        "evidence":"Searched Docker Hub for '%s' - none"%s.get("org","")}
FINDING_RULES=[_r_found,_r_clean]
INTEL_FIELDS=[("Org term","org"),("Images found","image_count"),("Images","images")]
@router.post("/api/recon/docker_hub_search")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="docker_hub_search",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,flat_field_keys=["images"])
def register(app): app.include_router(router)
