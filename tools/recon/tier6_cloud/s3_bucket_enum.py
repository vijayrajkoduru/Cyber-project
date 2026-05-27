"""s3_bucket_enum — VL-FORGE Recon (real, zero-FP)."""
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
        for region in ("s3.amazonaws.com","s3-us-west-2.amazonaws.com","s3-eu-west-1.amazonaws.com"):
            url = f"http://{name}.{region}/"
            c, _, b = await fetch(url, timeout=4)
            if c in (200, 403) and (b"<Code>NoSuchKey" in b or b"<ListBucketResult" in b or b"<Code>AccessDenied" in b):
                found.append({"bucket":name,"region":region,"status":c,"listable":c==200 and b"<ListBucketResult" in b})
                break
    ctx.state["candidates_tested"] = len(bucket_candidates(h)) * 3
    ctx.state["discovered_buckets"] = found
    ctx.source("S3 bucket name permutation + AWS error fingerprint")

RULES = [
    lambda s: {"name":"Public S3 Bucket Lists Contents","severity":"HIGH",
        "evidence":f"Bucket(s) publicly listable: {[b for b in s.get('discovered_buckets',[]) if b.get('listable')]}",
        "remediation":"Set bucket ACL to private; require IAM auth. AWS S3 Block Public Access setting.",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if any(b.get('listable') for b in s.get("discovered_buckets",[])) else None,
]

@router.post("/api/recon/s3_bucket_enum")
async def recon_s3_bucket_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="s3_bucket_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered Buckets","discovered_buckets"),("Candidates Tested","candidates_tested")])

def register(app):
    app.include_router(router)
