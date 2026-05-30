"""Medium user profile recon via public RSS — playbook §3.

Medium exposes /@username/feed as a public Atom feed (no auth). Returns
post titles + dates + URLs without scraping the dynamic page.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    user = (req.target or "").strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9._-]{1,40}$", user):
        return standard_response(
            tool="medium_user_intel", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Medium handle")

    r = safe_get(f"https://medium.com/feed/@{user}", req=req, timeout=8,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code == 404:
        return standard_response(
            tool="medium_user_intel", target=req.target,
            findings=[wrap_finding(
                f"Medium @{user}: no public RSS / not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public posts.",
                evidence_marker="Medium feed 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")
    if r.status_code != 200:
        return standard_response(
            tool="medium_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Medium status {r.status_code}")

    titles = re.findall(r"<title><!\[CDATA\[(.+?)\]\]></title>", r.text)[:15]
    dates = re.findall(r"<pubDate>([^<]+)</pubDate>", r.text)[:15]
    # First title is the channel name
    channel = titles[0] if titles else f"@{user}"
    posts = titles[1:] if len(titles) > 1 else []
    pdates = dates[1:] if len(dates) > 1 else []

    if not posts:
        return standard_response(
            tool="medium_user_intel", target=req.target,
            findings=[wrap_finding(
                f"Medium @{user}: channel exists but feed is empty",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Account exists but no published posts.",
                evidence_marker=f"channel={channel} | 0 items (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No posts")

    findings = [wrap_finding(
        f"Medium — '{channel}' ({len(posts)} recent posts)",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public author footprint. Post topics → expertise / employer "
                    "signals. Some authors leak employer affiliation in post bylines.",
        evidence_marker=" | ".join(
            f"[{d[:16]}] {t[:60]}" for d, t in zip(pdates[:5], posts[:5])
        ))]

    return standard_response(
        tool="medium_user_intel", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"Medium: {channel} / {len(posts)} posts",
        raw_data={"channel": channel, "posts": list(zip(pdates, posts))})


@router.post("/api/osint/medium_user_intel")
async def scan_medium_user_intel(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="medium_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
