"""social_handles — probe 12 social platforms for org-derived usernames.

VL-VERIFY deep: two real FP-class guards beyond the decorator's
reserved-domain skip:

  1. Brand-stem extraction: when target is "dasplc.com" we probe "dasplc"
     (not "dasplc.com" which most platforms 200 on as an invalid handle).

  2. Per-platform sentinel: BEFORE probing real candidate handles, probe
     a guaranteed-nonexistent random handle on each platform. If that
     also returns 200, the platform is sentinel-unreliable (Pinterest,
     Twitter, etc. return generic shells for invalid handles) — drop
     all hits on that platform.

For target=acme.com, generates 6 candidate handles (acme, acmecorp, acmehq,
acmeofficial, acme_inc, theacme) and HEAD-probes 12 platforms (72 checks
total). 200 (after sentinel check) = account exists.
"""
import asyncio
import secrets
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

try:
    from tools._payloads.osint.social_handles import (
        SOCIAL_PLATFORMS, derive_handles)
except ImportError:
    SOCIAL_PLATFORMS = [
        ("GitHub", "https://github.com/{handle}", [200]),
        ("X (Twitter)", "https://twitter.com/{handle}", [200]),
    ]
    def derive_handles(target):
        org = target.split(".")[0]
        return [org] if org else []


router = APIRouter()
WALL_CLOCK_S = 28

_KNOWN_TLDS = {"com", "net", "org", "co", "io", "ai", "app", "dev", "me",
                "us", "uk", "in", "de", "fr", "ca", "au"}


def _to_brand_stem(target: str) -> str:
    """Strip URL scheme/path/TLD, return brand stem suitable for handle search.
    'dasplc.com' -> 'dasplc' so we don't search 'dasplc.com' on platforms
    that 200 for any non-empty slug.
    """
    t = (target or "").strip().lower().lstrip("@")
    for pfx in ("http://", "https://"):
        if t.startswith(pfx):
            t = t[len(pfx):]
    t = t.split("/", 1)[0].split(":", 1)[0]
    if t.startswith("www."):
        t = t[4:]
    parts = t.split(".")
    if len(parts) >= 2 and parts[-1] in _KNOWN_TLDS:
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net"}:
            return parts[-3]
        return parts[-2]
    return t


def _probe(platform: str, url: str, ok_codes: list, req) -> dict | None:
    r = safe_get(url, req=req, timeout=4,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"},
                 allow_redirects=False)
    if r is None:
        return None
    if r.status_code in ok_codes:
        return {"platform": platform, "url": url, "status": r.status_code}
    return None


def _sentinel_unreliable_platforms(req) -> set:
    """Probe a random guaranteed-nonexistent handle on each platform. Any
    platform that returns 200 (success-equivalent) for the sentinel is
    flagged unreliable — its real-handle 200 hits are FPs."""
    sentinel = "vl_no_exist_" + secrets.token_hex(8)
    unreliable = set()
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {}
        for platform, tpl, ok_codes in SOCIAL_PLATFORMS:
            url = tpl.format(handle=sentinel)
            futs[pool.submit(_probe, platform, url, ok_codes, req)] = platform
        for fut, platform in futs.items():
            try:
                if fut.result(timeout=6):
                    unreliable.add(platform)
            except Exception:
                continue
    return unreliable


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    # VL-VERIFY deep: brand-stem extraction so we search "dasplc" not
    # "dasplc.com" (most platforms 200 on the latter)
    brand = _to_brand_stem(target)
    if not brand:
        return standard_response(tool="social_handles", target=req.target,
            findings=[], tests_performed=0, vulnerable=False,
            skipped_reason="could not derive brand stem from target")

    handles = derive_handles(brand)
    if not handles:
        return standard_response(tool="social_handles", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"could not derive handles from brand '{brand}'")

    # VL-VERIFY deep: sentinel probe — drop any platform that 200s for a
    # known-nonexistent handle.
    unreliable = _sentinel_unreliable_platforms(req)

    hits = []
    tests = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = []
        for handle in handles:
            for platform, tpl, ok_codes in SOCIAL_PLATFORMS:
                if platform in unreliable:
                    continue  # platform is sentinel-unreliable
                url = tpl.format(handle=handle)
                futs.append(pool.submit(_probe, platform, url, ok_codes, req))
                tests += 1
        for fut in futs:
            try:
                result = fut.result(timeout=6)
                if result:
                    hits.append(result)
            except Exception:
                continue

    findings = []
    if hits:
        sample = [f"{h['platform']}: {h['url']}" for h in hits[:15]]
        findings.append(wrap_finding(
            f"{len(hits)} social media account(s) match org-derived handles (sentinel-verified)",
            severity="LOW", cvss="2.0",
            cwe="CWE-200", owasp="A05:2021",
            verified_exploit=True,
            remediation=("Defensively register matching handles you don't own; "
                        "the lookup is informational, not a vulnerability. "
                        "Squat-takeover risk on platforms allowing name reuse."),
            evidence_marker=("; ".join(sample) +
                              (f" [sentinel-dropped: {sorted(unreliable)}]"
                                if unreliable else ""))))
    else:
        findings.append(wrap_finding(
            f"No social handles match brand '{brand}' on probed platforms",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="No social surface — handles available for defensive registration.",
            evidence_marker=(f"{tests} probes, 0 hits"
                              + (f" [sentinel-dropped: {sorted(unreliable)}]"
                                  if unreliable else ""))))

    return standard_response(
        tool="social_handles", target=req.target, findings=findings,
        tests_performed=tests, vulnerable=False,
        tests_summary=(f"{len(handles)} handles × "
                        f"{len(SOCIAL_PLATFORMS) - len(unreliable)} reliable platforms; "
                        f"{len(hits)} hits"),
        raw_data={"hits": hits, "handles_tried": handles,
                   "brand_stem": brand,
                   "platforms_sentinel_dropped": sorted(unreliable)})


@router.post("/api/osint/social_handles")
@vl_verify()
async def scan_social(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="social_handles", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
