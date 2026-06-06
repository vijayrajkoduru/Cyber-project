"""s3_bucket_enum — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
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

def _r_chain_handoff(s):
    buckets = s.get("discovered_buckets") or []
    if not buckets:
        return None
    chain_next = []
    reasons = []
    # Any bucket discovered -> perm audit + env leak hunt
    chain_next.extend(["bucket_perm_audit", "exposed_env_scan"])
    reasons.append(f"{len(buckets)} bucket(s) -> bucket_perm_audit + exposed_env_scan")
    # Public/listable bucket -> secrets sweep
    listable = [b for b in buckets if b.get("listable")]
    if listable:
        for s_name in ("bucket_perm_audit", "git_secrets_scan"):
            if s_name not in chain_next:
                chain_next.append(s_name)
        reasons.append(f"{len(listable)} listable -> git_secrets_scan")
    # Subdomain-style bucket naming -> takeover check
    sub_named = [b for b in buckets if "." in (b.get("bucket") or "") or "-" in (b.get("bucket") or "")]
    if sub_named:
        if "subdomain_takeover" not in chain_next:
            chain_next.append("subdomain_takeover")
        reasons.append(f"{len(sub_named)} subdomain-named -> subdomain_takeover")
    # Many buckets -> fan out to other cloud providers
    if len(buckets) >= 2:
        for s_name in ("gcs_bucket_enum", "azure_blob_enum"):
            if s_name not in chain_next:
                chain_next.append(s_name)
        reasons.append("multi-bucket -> gcs_bucket_enum + azure_blob_enum")
    # CloudFront origin hint
    cf_hint = [b for b in buckets if "cloudfront" in (b.get("bucket") or "").lower()]
    if cf_hint:
        if "cloudfront_disco" not in chain_next:
            chain_next.append("cloudfront_disco")
        reasons.append("cloudfront-named -> cloudfront_disco")
    # Dev/staging env naming -> high-value secret leak chain
    env_named = [b for b in buckets if re.search(r"(dev|stag|staging|test|qa|uat|preprod)", (b.get("bucket") or "").lower())]
    if env_named:
        for s_name in ("exposed_env_scan", "git_secrets_scan"):
            if s_name not in chain_next:
                chain_next.append(s_name)
        reasons.append(f"{len(env_named)} non-prod env name(s) -> exposed_env_scan + git_secrets_scan")
    if not chain_next:
        return None
    return {
        "name": "Cross-module chain handoff - S3 buckets discovered for follow-up",
        "severity": "INFO",
        "evidence": f"Found {len(buckets)} S3 bucket(s); suggests {len(chain_next)} follow-up scanner(s): " + "; ".join(reasons),
        "remediation": "S3 buckets commonly leak .env / .git / configs. Run bucket_perm_audit + exposed_env_scan + git_secrets_scan against each.",
        "cwe": "CWE-1006",
        "chain_next": chain_next,
        "discovery_method": "s3_to_data_leak_chain",
        "source_stage": "chain_handoff",
        "confidence": "INFO",
    }

RULES = [
    lambda s: {"name":"Public S3 Bucket Lists Contents","severity":"HIGH",
        "evidence":f"Bucket(s) publicly listable: {[b for b in s.get('discovered_buckets',[]) if b.get('listable')]}",
        "remediation":"Set bucket ACL to private; require IAM auth. AWS S3 Block Public Access setting.",
        "cwe":"CWE-284","owasp":"A01:2021"
    } if any(b.get('listable') for b in s.get("discovered_buckets",[])) else None,
    _r_chain_handoff,
]

@router.post("/api/recon/s3_bucket_enum")
async def recon_s3_bucket_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="s3_bucket_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Discovered Buckets","discovered_buckets"),("Candidates Tested","candidates_tested")])

def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners trigger us via
#  _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "s3_bucket_enum", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("s3_bucket_enum", _chain_callable)
