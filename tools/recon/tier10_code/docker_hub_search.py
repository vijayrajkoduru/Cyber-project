"""docker_hub_search — VL-FORGE. Own-code, no key: search Docker Hub for org public images."""
import asyncio, requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
def _search(term):
    try:
        r=requests.get("https://hub.docker.com/v2/search/repositories/",
            params={"query":term,"page_size":25}, timeout=8, headers={"User-Agent":"VulnusLab/1.0"})
        return r.json() if r.status_code==200 else None
    except Exception: return None
async def gather(ctx):
    org=str(ctx.host).split(".")[0]
    j=await asyncio.to_thread(_search, org)
    if not j: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.source("dockerhub")
    hits=[{"name":x.get("repo_name") or x.get("name"),"stars":x.get("star_count",0)}
          for x in (j.get("results") or [])
          if org.lower() in str(x.get("repo_name") or x.get("name") or "").lower()]
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
