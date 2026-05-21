"""recon_bucket_perms — check actual ACL permissions on discovered buckets."""
import asyncio, aiohttp, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


async def recon_bucket_perms_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    name = recon_host(req.target).split(".")[0]
    findings, perm_results = [], []
    suffixes = ["", "-prod", "-staging", "-dev", "-backup", "-uploads",
                "-files", "-data", "-assets", "-media", "-public", "-private",
                "-internal", "-static", "-cdn"]
    candidates = []
    for sfx in suffixes:
        bn = name + sfx
        candidates.append((f"https://{bn}.s3.amazonaws.com", "aws-s3", bn))
        candidates.append((f"https://storage.googleapis.com/{bn}", "gcs", bn))
        candidates.append((f"https://{bn}.blob.core.windows.net/?comp=list", "azure", bn))

    async def _check(session, url, provider, bn):
        result = {"url": url, "provider": provider, "bucket": bn,
                  "exists": False, "public_list": False}
        try:
            t = aiohttp.ClientTimeout(total=5)
            async with session.head(url, timeout=t, allow_redirects=False) as r:
                if r.status not in (200, 403):
                    return None
                result["exists"] = True
            async with session.get(url + ("" if provider != "aws-s3" else "/"), timeout=t) as r:
                text = await r.text()
                if r.status == 200:
                    if "<ListBucketResult" in text or "<EnumerationResults" in text:
                        result["public_list"] = True
                        objs = re.findall(r"<(?:Key|Name)>([^<]+)</(?:Key|Name)>", text)[:5]
                        result["sample_objects"] = objs
            return result
        except Exception:
            return result if result["exists"] else None

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[_check(session, u, p, n) for u, p, n in candidates],
                                         return_exceptions=True)
    for r in results:
        if not isinstance(r, dict): continue
        if r.get("exists"): perm_results.append(r)
        if r.get("public_list"):
            findings.append({"title": f"Public-listable cloud bucket: {r['bucket']} ({r['provider']})",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-200", "owasp": "A01:2021",
                "evidence": f"Bucket {r['bucket']} on {r['provider']} allows anonymous listing",
                "remediation": "Apply private bucket policy. AWS: Block Public Access. GCS: IAM restrict."})
    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "buckets_tested": len(candidates),
            "buckets_exist": len(perm_results),
            "buckets_public": sum(1 for r in perm_results if r.get("public_list")),
            "details": perm_results[:30],
            "engine": f"async aiohttp bucket ACL probe ({len(candidates)} candidates)"}



# VLERR-WRAP-V1
@router.post("/api/recon/bucket_perms")
async def recon_bucket_perms(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_bucket_perms_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"bucket_perms scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": f"{type(_e).__name__}: {str(_e)[:300]}"}

def register(app):
    app.include_router(router)
