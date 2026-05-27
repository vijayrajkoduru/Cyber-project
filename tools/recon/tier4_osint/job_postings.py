"""job_postings — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]
    # Greenhouse public job board pattern
    code, d = await get_json(f"https://boards-api.greenhouse.io/v1/boards/{name}/jobs")
    jobs = (d or {{}}).get("jobs",[]) if isinstance(d, dict) else []
    ctx.state["jobs_count"] = len(jobs)
    ctx.state["job_titles"] = [j.get("title") for j in jobs[:15]]
    ctx.state["tech_keywords"] = sorted(set(kw for j in jobs for kw in re.findall(r"\b(Python|Go|Rust|Java|Kubernetes|AWS|GCP|Azure|Terraform|Docker|React|Node|Django|FastAPI|Postgres|Redis|Kafka|Elasticsearch)\b", j.get("title","")+" "+(j.get("content","") or ""), re.I)))
    ctx.source("Greenhouse public jobs API")

RULES = [

]

@router.post("/api/recon/job_postings")
async def recon_job_postings(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="job_postings",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Jobs Count","jobs_count"),("Job Titles","job_titles"),("Tech Keywords","tech_keywords")])

def register(app):
    app.include_router(router)
