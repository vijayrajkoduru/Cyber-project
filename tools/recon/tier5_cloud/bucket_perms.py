"""Bucket Permission Audit v2 — VL-FORGE pattern.

Route: /api/recon/bucket_perms

Sources (parallel):
  1. Bucket existence HEAD probe (AWS S3 / GCS / Azure Blob)
  2. List operation test (public listing via XML response parsing)
  3. Sample-object name extraction (when listable)
"""
import asyncio
import re

import aiohttp

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.bucket_perms_findings import BUCKET_PERMS_FINDING_RULES

router = APIRouter()


_SUFFIXES = ["", "-prod", "-staging", "-dev", "-backup", "-uploads",
              "-files", "-data", "-assets", "-media", "-public", "-private",
              "-internal", "-static", "-cdn", "-archive"]


async def _check(session, url, provider, bn):
    """Test HEAD + GET (listing) on a candidate bucket URL."""
    result = {"url": url, "provider": provider, "bucket": bn,
              "exists": False, "public_list": False, "public_read": False,
              "sample_objects": []}
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        async with session.head(url, timeout=timeout,
                                 allow_redirects=False) as r:
            if r.status not in (200, 403):
                return None
            result["exists"] = True
        # GET — test for listable XML response
        list_url = url + ("/" if provider == "aws-s3-vhost" else "")
        async with session.get(list_url, timeout=timeout) as r:
            if r.status == 200:
                text = await r.text()
                if "<ListBucketResult" in text or "<EnumerationResults" in text:
                    result["public_list"] = True
                    objs = re.findall(r"<(?:Key|Name)>([^<]+)</(?:Key|Name)>",
                                       text)[:5]
                    result["sample_objects"] = objs
                else:
                    # 200 but not XML → public file index page
                    result["public_read"] = True
        return result
    except Exception:
        return result if result["exists"] else None


async def gather(ctx: ScanContext):
    name = ctx.host.split(".")[0]

    candidates = []
    for sfx in _SUFFIXES:
        bn = name + sfx
        candidates.append((f"https://{bn}.s3.amazonaws.com", "aws-s3-vhost", bn))
        candidates.append((f"https://storage.googleapis.com/{bn}", "gcs", bn))
        candidates.append((f"https://{bn}.blob.core.windows.net/?comp=list",
                            "azure", bn))

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[
            _check(session, u, p, n) for u, p, n in candidates
        ], return_exceptions=True)

    perm_details = []
    for r in results:
        if not isinstance(r, dict): continue
        if r.get("exists"): perm_details.append(r)

    ctx.state["buckets_tested"] = len(candidates)
    ctx.state["buckets_exist"] = len(perm_details)
    ctx.state["buckets_public"] = sum(1 for r in perm_details
                                       if r.get("public_list") or r.get("public_read"))
    ctx.state["permission_details"] = perm_details[:30]

    if candidates:
        ctx.source(f"bucket-head-probe-{len(candidates)}")
    if perm_details:
        ctx.source(f"bucket-list-test-{len(perm_details)}")


INTEL_FIELDS = [
    ("Candidates tested",       "buckets_tested"),
    ("Buckets exist",            "buckets_exist"),
    ("Publicly accessible",     "buckets_public"),
    ("Sample listable objects", "sample_objects_display"),
]


@router.post("/api/recon/bucket_perms")
async def recon_bucket_perms(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        pd = ctx.state.get("permission_details") or []
        public = [b for b in pd if b.get("public_list") or b.get("public_read")]
        if public:
            samples = []
            for b in public[:3]:
                so = b.get("sample_objects") or []
                if so:
                    samples.append(f"{b['bucket']}: {', '.join(so[:3])}")
            if samples:
                ctx.state["sample_objects_display"] = "; ".join(samples)

    return await run_scanner(
        host=host, tool="bucket_perms",
        gather_func=gather_with_display,
        finding_rules=BUCKET_PERMS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["buckets_exist", "buckets_public", "buckets_tested"],
    )


def register(app):
    app.include_router(router)
