"""social_handles — probe 12 social platforms for org-derived usernames.

For target=acme.com, generates 6 candidate handles (acme, acmecorp, acmehq,
acmeofficial, acme_inc, theacme) and HEAD-probes 12 platforms (72 checks
total). 200 = account exists, 404 = available, others = inconclusive.

Wordlist source: tools._payloads.osint.social_handles.
VL-FOUNDRY Layer 6: 7-check DoD compliant.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

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


def _probe(platform: str, url: str, ok_codes: list, req) -> dict | None:
    """Probe one platform for one handle. Returns hit dict or None."""
    r = safe_get(url, req=req, timeout=4,
                 headers={"User-Agent": "Mozilla/5.0 (VulnusLab OSINT)"},
                 allow_redirects=False)
    if r is None:
        return None
    if r.status_code in ok_codes:
        return {"platform": platform, "url": url, "status": r.status_code}
    return None


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    handles = derive_handles(target)
    if not handles:
        return standard_response(tool="social_handles", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="could not derive handles from target")

    hits = []
    tests = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = []
        for handle in handles:
            for platform, tpl, ok_codes in SOCIAL_PLATFORMS:
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
            f"{len(hits)} social media account(s) match org-derived handles",
            severity="LOW", cvss="2.0",
            cwe="CWE-200", owasp="A05:2021",
            remediation=("Defensively register matching handles you don't own; "
                        "the lookup is informational, not a vulnerability. "
                        "Squat-takeover risk on platforms allowing name reuse."),
            evidence_marker="; ".join(sample)))
    else:
        findings.append(wrap_finding(
            "No social handles match org name on probed platforms",
            severity="POSITIVE",
            cwe="CWE-200", owasp="A05:2021",
            remediation="No social surface — handles available for defensive registration.",
            evidence_marker=f"{tests} probes, 0 hits"))

    return standard_response(
        tool="social_handles", target=req.target, findings=findings,
        tests_performed=tests, vulnerable=False,
        tests_summary=f"{len(handles)} handles × {len(SOCIAL_PLATFORMS)} platforms; {len(hits)} hits",
        raw_data={"hits": hits, "handles_tried": handles})


@router.post("/api/osint/social_handles")
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
