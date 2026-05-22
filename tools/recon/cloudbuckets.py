"""Cloud Bucket Finder v2 — VL-FORGE pattern.

Route: /api/recon/cloudbuckets

Sources (parallel):
  1. AI-curated 270-pattern bucket-name permutation library
     (loaded from tools/_payloads/recon/cloud_bucket_patterns.json if present)
  2. Built-in fallback patterns (~70 combinations across 7 providers)
  3. Parallel HEAD probes to verify bucket existence/openness

Findings (~7 rules):
  CRITICAL: open buckets (AWS S3 / GCS / Azure Blob — each provider)
  INFO    : bucket exists but auth-required, multi-provider footprint
  POSITIVE: no buckets found via name permutation
"""
import asyncio
import json
import pathlib

import aiohttp

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.cloudbuckets_findings import CLOUDBUCKETS_FINDING_RULES

router = APIRouter()


# Built-in fallback patterns (used if AI library not present)
_SUFFIXES = [
    "", "-prod", "-production", "-staging", "-stage", "-dev",
    "-test", "-qa", "-uat", "-sandbox", "-backup", "-backups",
    "-uploads", "-files", "-data", "-assets", "-media",
    "-public", "-private", "-internal", "-archive", "-logs",
    "-cdn", "-static", "-app", "-web", "-www",
]
_PREFIXES = ["", "prod-", "staging-", "dev-", "test-", "backup-"]

# Provider URL templates ({bn} = bucket name placeholder)
_PROVIDER_TEMPLATES = [
    ("AWS S3 (vhost)",   "https://{bn}.s3.amazonaws.com"),
    ("AWS S3 (path)",    "https://s3.amazonaws.com/{bn}"),
    ("GCS",              "https://storage.googleapis.com/{bn}"),
    ("Azure Blob",       "https://{bn}.blob.core.windows.net"),
    ("DO Spaces",        "https://{bn}.digitaloceanspaces.com"),
    ("Linode Objects",   "https://{bn}.linodeobjects.com"),
    ("Wasabi",           "https://s3.wasabisys.com/{bn}"),
]


def _load_ai_patterns():
    try:
        p = pathlib.Path(__file__).parent.parent / "_payloads" / "recon" / "cloud_bucket_patterns.json"
        if p.exists():
            data = json.loads(p.read_text())
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "patterns" in data:
                return data["patterns"]
    except Exception:
        pass
    return None


_AI_PATTERNS = _load_ai_patterns()


def _build_candidates(host: str):
    """Generate candidate bucket URLs from base host name."""
    name = host.split(".")[0]
    if _AI_PATTERNS:
        # AI library provides full pattern strings — substitute {name}
        bucket_names = [p.replace("{name}", name) for p in _AI_PATTERNS]
    else:
        bucket_names = set()
        for pfx in _PREFIXES:
            for sfx in _SUFFIXES:
                bucket_names.add(pfx + name + sfx)
        bucket_names = list(bucket_names)

    candidates = []
    for bn in bucket_names:
        for provider, tmpl in _PROVIDER_TEMPLATES:
            candidates.append((provider, tmpl.format(bn=bn), bn))
    return candidates


async def _probe(session, provider, url, bn):
    try:
        async with session.head(url, allow_redirects=False) as r:
            return (provider, url, bn, r.status)
    except Exception:
        return (provider, url, bn, None)


async def gather(ctx: ScanContext):
    candidates = _build_candidates(ctx.host)
    timeout = aiohttp.ClientTimeout(total=5)
    open_buckets = []
    existing_buckets = []
    providers_found = set()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = await asyncio.gather(*[
            _probe(session, prov, url, bn) for prov, url, bn in candidates
        ])
    for prov, url, bn, status in results:
        if status in (200, 403):
            existing_buckets.append({"url": url, "bucket": bn,
                                     "provider": prov, "status": status})
            providers_found.add(prov)
            if status == 200:
                open_buckets.append(url)

    ctx.state["open_buckets"] = open_buckets
    ctx.state["existing_buckets"] = existing_buckets
    ctx.state["providers_found"] = sorted(providers_found)
    ctx.state["patterns_tested"] = len(candidates)
    ctx.state["bucket_names_tested"] = len(set(c[2] for c in candidates))

    if candidates:
        ctx.source(f"bucket-permutation-{ctx.state['bucket_names_tested']}-names")
    if existing_buckets:
        ctx.source(f"head-probe-{len(existing_buckets)}-hits")


INTEL_FIELDS = [
    ("Patterns tested",     "patterns_tested"),
    ("Bucket names tested", "bucket_names_tested"),
    ("Providers found",     "providers_display"),
    ("Open buckets",         "open_display"),
    ("Existing (private)",  "existing_display"),
]


@router.post("/api/recon/cloudbuckets")
async def recon_cloudbuckets(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        pf = ctx.state.get("providers_found") or []
        if pf: ctx.state["providers_display"] = ", ".join(pf)
        ob = ctx.state.get("open_buckets") or []
        if ob: ctx.state["open_display"] = ", ".join(ob[:3])
        eb = ctx.state.get("existing_buckets") or []
        if eb:
            ctx.state["existing_display"] = ", ".join(
                str(b.get("url", b))[:60] for b in eb[:3])

    return await run_scanner(
        host=host, tool="cloudbuckets",
        gather_func=gather_with_display,
        finding_rules=CLOUDBUCKETS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["open_buckets", "existing_buckets"],
    )


def register(app):
    app.include_router(router)
