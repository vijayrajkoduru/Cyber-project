"""Job Postings v2 — VL-FORGE. Indeed + LinkedIn scrape for tech stack hints."""
import asyncio, requests, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
router=APIRouter()
def _g(u,t=12):
    try:
        r=requests.get(u,timeout=t,headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code==200: return r.text
    except: pass
    return None
async def gather(ctx):
    org=ctx.host.split(".")[0]
    indeed=await asyncio.to_thread(_g,f"https://www.indeed.com/jobs?q=%22{org}%22&l=&filter=0")
    bing_jobs=await asyncio.to_thread(_g,f"https://www.bing.com/search?q=site%3Alinkedin.com%2Fjobs+%22{org}%22&count=20")
    tech_stack=set()
    keywords=["aws","azure","gcp","kubernetes","docker","python","golang","java","javascript",
        "react","vue","angular","postgres","mysql","mongodb","redis","kafka","terraform","ansible",
        "jenkins","gitlab","github actions","graphql","grpc","grafana","prometheus"]
    job_count_indicator=0
    for src in [indeed,bing_jobs]:
        if not src: continue
        ctx.source("scrape" if src==indeed else "bing")
        low=src.lower()
        for k in keywords:
            if k in low: tech_stack.add(k)
        if "jobs" in low: job_count_indicator+=1
    ctx.state["tech_stack_hints"]=sorted(tech_stack)
    ctx.state["job_listings_likely"]=job_count_indicator>0
def _r_tech(s):
    ts=s.get("tech_stack_hints") or []
    if not ts: return None
    return {"name":f"Tech stack leaked via job postings ({len(ts)} indicators)","severity":"INFO","cwe":"T1591",
        "evidence":f"Sample: {', '.join(ts[:8])}",
        "remediation":"Job posts reveal infra. Audit posts for sensitive tool names."}
def _r_hiring(s):
    if not s.get("job_listings_likely"): return None
    return {"name":"Active hiring detected","severity":"INFO",
        "evidence":"Job listings indexed — useful for social engineering pretexts"}
FINDING_RULES=[_r_tech,_r_hiring]
INTEL_FIELDS=[("Tech stack hints","tech_stack_hints"),("Hiring active","job_listings_likely")]
@router.post("/api/recon/job_postings")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="job_postings",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["tech_stack_hints","job_listings_likely"])
def register(app): app.include_router(router)
