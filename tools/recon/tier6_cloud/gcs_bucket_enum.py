"""gcs_bucket_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
from tools.recon._cloud_helpers import bucket_candidates

router = APIRouter()

async def gather(ctx: ScanContext):
    h = ctx.host
    found = []
    for name in bucket_candidates(h):
        url = f"https://storage.googleapis.com/{name}/"
        c, _, b = await fetch(url, timeout=4)
        if c in (200,403) and (b"NoSuchBucket" not in b) and (b"<ListBucketResult" in b or b"AccessDenied" in b):
            found.append({"bucket":name,"status":c,"listable":c==200 and b"<ListBucketResult" in b})
    ctx.state["discovered_buckets"] = found
    ctx.source("GCS bucket name permutation")

RULES = [
    lambda s: {"name":"Public GCS Bucket Lists Contents","severity":"HIGH",
        "evidence":f"Listable: {[b for b in s.get('discovered_buckets',[]) if b.get('listable')]}",
        "remediation":"gsutil iam ch -d allUsers:objectViewer gs://<bucket>; remove allUsers/allAuthenticatedUsers grants",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if any(b.get('listable') for b in s.get("discovered_buckets",[])) else None,
]

@router.post("/api/recon/gcs_bucket_enum")
async def recon_gcs_bucket_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gcs_bucket_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered Buckets","discovered_buckets")])

def register(app):
    app.include_router(router)
