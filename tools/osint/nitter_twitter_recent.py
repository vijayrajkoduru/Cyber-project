"""Twitter/X recent tweets via public Nitter mirror — playbook §3 #33.

Twitter killed the free API tier in 2023. Nitter mirrors scrape Twitter
without an account. Falls through 3 known Nitter mirrors for resiliency.
Returns the latest ~10 tweets (text, timestamp).

Real probe via HTML parse. Mirrors come and go — gracefully skips if all
3 are down.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 20
MIRRORS = ["https://nitter.privacydev.net", "https://nitter.poast.org",
            "https://nitter.net"]


def _do_scan(req: ScanRequest) -> dict:
    handle = (req.target or "").strip().lstrip("@")
    if not handle or not re.match(r"^[A-Za-z0-9_]{1,15}$", handle):
        return standard_response(
            tool="nitter_twitter_recent", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Twitter handle")

    body = None
    used_mirror = None
    for m in MIRRORS:
        r = safe_get(f"{m}/{handle}/with_replies", req=req, timeout=7,
                      headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
        if r is not None and r.status_code == 200 and "tweet-content" in (r.text or ""):
            body = r.text; used_mirror = m
            break

    if body is None:
        return standard_response(
            tool="nitter_twitter_recent", target=req.target, findings=[],
            tests_performed=len(MIRRORS), vulnerable=False,
            skipped_reason="all 3 Nitter mirrors unreachable (Nitter ecosystem is fragile)")

    tweets = re.findall(r'<div class="tweet-content[^"]*"[^>]*>(.+?)</div>',
                          body, re.DOTALL)[:10]
    timestamps = re.findall(r'<span class="tweet-date"[^>]*><a[^>]*title="([^"]+)"',
                              body)[:10]
    tweets_clean = [re.sub(r"<[^>]+>", " ", t).strip()[:200] for t in tweets]

    if not tweets_clean:
        return standard_response(
            tool="nitter_twitter_recent", target=req.target,
            findings=[wrap_finding(
                f"@{handle} — no recent tweets or account locked/suspended",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either account is private, suspended, or has no posts.",
                evidence_marker=f"Nitter via {used_mirror} returned 0 tweets (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No tweets via Nitter")

    findings = [wrap_finding(
        f"@{handle} — {len(tweets_clean)} recent tweet(s) via Nitter",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public timeline data. For OSINT pivot: extract mentions, "
                    "hashtags, posting times (infer timezone), URL shorteners.",
        evidence_marker=" | ".join(
            f"[{ts}] {tw[:80]}" for ts, tw in zip(timestamps, tweets_clean[:5])
        ) + " (via " + used_mirror + ")")]

    return standard_response(
        tool="nitter_twitter_recent", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"@{handle}: {len(tweets_clean)} tweets via Nitter",
        raw_data={"handle": handle, "tweets": tweets_clean,
                   "timestamps": timestamps, "mirror": used_mirror})


@router.post("/api/osint/nitter_twitter_recent")
async def scan_nitter_twitter_recent(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="nitter_twitter_recent", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
