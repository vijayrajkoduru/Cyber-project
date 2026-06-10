"""cloudfront_disco — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

# Header fingerprints that identify a CloudFront origin or distribution edge.
# Each tuple is (header_name_substring, evidence_label).
_CLOUDFRONT_FINGERPRINTS = [
    ("x-amz-cf-id",      "AWS CloudFront edge request id"),
    ("x-amz-cf-pop",     "AWS CloudFront PoP code"),
    ("x-cache",          "Edge cache marker (often CloudFront/Hit/Miss)"),
    ("via",              "Via header (often 1.1 ...cloudfront.net)"),
    ("server",           "Server header advertising CloudFront"),
    ("x-amz-id-2",       "AWS request id (S3 origin via CloudFront)"),
    ("x-amz-request-id", "AWS request id"),
    ("cloudfront",       "CloudFront token in any header"),
]


async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    # Probe a couple of paths concurrently — CloudFront sometimes only
    # surfaces its headers on cache-miss responses, so / and a random path
    # give a more reliable fingerprint than a single hit.
    async def _probe(path):
        c, h, _ = await fetch(base.rstrip("/") + path)
        return (c, h or {})
    results = await asyncio.gather(_probe("/"), _probe("/__cloudfront_check__"))
    merged = {}
    for _c, h in results:
        for k, v in h.items():
            merged.setdefault(k, v)
    hdr_blob = " ".join(f"{k}:{v}" for k, v in merged.items()).lower()
    hits = [(name, label) for name, label in _CLOUDFRONT_FINGERPRINTS
            if name in hdr_blob and ("cloudfront" in hdr_blob or "amz" in name)]
    ctx.state["cloudfront_detected"] = bool(hits)
    ctx.state["evidence_headers"] = {k: v for k, v in merged.items()
                                      if "amz" in k.lower() or "cloudfront" in k.lower()}
    ctx.state["fingerprint_hits"] = [label for _, label in hits]
    ctx.source("CloudFront header fingerprint")

RULES = [

]

@router.post("/api/recon/cloudfront_disco")
async def recon_cloudfront_disco(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="cloudfront_disco",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Cloudfront Detected","cloudfront_detected"),("Evidence Headers","evidence_headers")])

def register(app):
    app.include_router(router)
