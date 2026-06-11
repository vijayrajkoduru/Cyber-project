"""s3_bucket_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch
from tools.recon._cloud_helpers import bucket_candidates

router = APIRouter()

_S3_REGIONS = ("s3.amazonaws.com",
               "s3-us-west-2.amazonaws.com",
               "s3-eu-west-1.amazonaws.com")


async def gather(ctx: ScanContext):
    h = ctx.host
    names = list(bucket_candidates(h))
    pairs = [(n, r) for n in names for r in _S3_REGIONS]
    async def _probe(name, region):
        url = f"http://{name}.{region}/"
        c, _, b = await fetch(url, timeout=4)
        if c in (200, 403) and (b"<Code>NoSuchKey" in b or b"<ListBucketResult" in b or b"<Code>AccessDenied" in b):
            return {"bucket":name,"region":region,"status":c,"listable":c==200 and b"<ListBucketResult" in b}
        return None
    results = await asyncio.gather(*(_probe(n, r) for n, r in pairs))
    # Keep first hit per bucket (mimic the original break behaviour).
    seen = set(); found = []
    for r in results:
        if r and r["bucket"] not in seen:
            seen.add(r["bucket"]); found.append(r)
    ctx.state["candidates_tested"] = len(pairs)
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
