"""gcs_bucket_enum — VL-FORGE Recon (real, zero-FP).

ZERO-FP-V1 (2026-06-06): bucket discovery now uses apex-extracted org name
(via _cloud_helpers.bucket_candidates) so 'app.vulnuslab.com' generates
'vulnuslab-*' permutations, not generic 'app-*' that hits random orgs.

Plus an ownership-confidence layer: any bucket whose name doesn't contain
the customer's full brand string is treated as LOW-CONFIDENCE and emitted
as a MEDIUM intel finding rather than a HIGH finding. This prevents
generic-substring matches (e.g. 'public-app' from an unrelated company)
from triggering false HIGH alerts on customer reports.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch
from tools.recon._cloud_helpers import bucket_candidates
from tools.recon._targeting import get_org_name

router = APIRouter()


async def gather(ctx: ScanContext):
    h = ctx.host
    org_name = (get_org_name(h) or "").lower()
    ctx.state["org_name_used"] = org_name
    names = list(bucket_candidates(h))
    if not names:
        ctx.state["skipped_reason"]=f"Brand name '{org_name}' too generic to enumerate GCS buckets without false-positive risk"
        return

    async def _probe(name):
        url = f"https://storage.googleapis.com/{name}/"
        c, _, b = await fetch(url, timeout=4)
        if c in (200, 403) and (b"NoSuchBucket" not in b) and (b"<ListBucketResult" in b or b"AccessDenied" in b):
            # Ownership confidence: bucket name must CONTAIN the customer's
            # brand string. With the cloud_helpers fix above this should
            # always be True, but we double-check to harden against any
            # cross-cutting permutation logic in future.
            confidence = "HIGH" if org_name and org_name in name.lower() else "LOW"
            return {"bucket": name, "status": c,
                    "listable": (c == 200 and b"<ListBucketResult" in b),
                    "ownership_confidence": confidence}
        return None

    results = await asyncio.gather(*(_probe(n) for n in names))
    ctx.state["discovered_buckets"] = [r for r in results if r]
    ctx.source("GCS bucket name permutation (apex-extracted brand)")


def _r_high_conf(s):
    """HIGH only when the bucket name positively contains the customer's
    brand AND the bucket lists contents publicly."""
    hits = [b for b in s.get("discovered_buckets", [])
            if b.get("listable") and b.get("ownership_confidence") == "HIGH"]
    if not hits:
        return None
    return {"name": "Public GCS Bucket Lists Contents", "severity": "HIGH",
            "evidence": f"Listable: {hits}",
            "remediation": "gsutil iam ch -d allUsers:objectViewer gs://<bucket>; remove allUsers/allAuthenticatedUsers grants",
            "cwe": "CWE-284", "owasp": "A01:2021"}


def _r_low_conf(s):
    """Low-confidence matches go to INFO so they're still surfaced for
    review but don't inflate the HIGH count."""
    hits = [b for b in s.get("discovered_buckets", [])
            if b.get("ownership_confidence") == "LOW"]
    if not hits:
        return None
    return {"name": f"{len(hits)} similarly-named public GCS bucket(s) (ownership unconfirmed)",
            "severity": "INFO",
            "evidence": f"Buckets matched permutation pattern but name doesn't contain full brand: {[b['bucket'] for b in hits[:5]]}",
            "remediation": "Manual review: verify whether these buckets belong to your org.",
            "cwe": "CWE-200"}


RULES = [_r_high_conf, _r_low_conf]


@router.post("/api/recon/gcs_bucket_enum")
async def recon_gcs_bucket_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="gcs_bucket_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Org name used", "org_name_used"),
                                            ("Discovered Buckets", "discovered_buckets")])


def register(app):
    app.include_router(router)
