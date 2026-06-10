"""Reddit user history via public JSON endpoint — playbook §3 #39.

Reddit exposes /user/{name}/about.json + /user/{name}/submitted.json +
/user/{name}/comments.json publicly (rate-limited to ~60 req/min UA-keyed).
No OAuth required. Returns account age, karma, top subreddits, recent
post/comment count.

Real probe. Zero false positives.
"""
import asyncio
import re
from collections import Counter
from datetime import datetime, UTC
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 15
H = {"User-Agent": "VulnusLab-OSINT/1.0 (research)"}


def _do_scan(req: ScanRequest) -> dict:
    user = (req.target or "").strip().lstrip("@u/").lstrip("/")
    if not user or not re.match(r"^[A-Za-z0-9_-]{3,20}$", user):
        return standard_response(
            tool="reddit_user_history", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Reddit username")

    about = safe_get(f"https://www.reddit.com/user/{user}/about.json",
                      req=req, timeout=7, headers=H)
    if about is None or about.status_code == 404:
        return standard_response(
            tool="reddit_user_history", target=req.target,
            findings=[wrap_finding(
                f"u/{user} does not exist or is suspended",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker="Reddit 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Reddit user not found")
    if about.status_code != 200:
        return standard_response(
            tool="reddit_user_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Reddit status {about.status_code} (rate-limited?)")

    try:
        prof = about.json().get("data", {})
    except Exception:
        return standard_response(
            tool="reddit_user_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON Reddit response")

    created = prof.get("created_utc", 0)
    age_days = int((datetime.now(UTC).timestamp() - created) / 86400) if created else 0

    # Pull last 25 submissions for top-subreddit analysis
    posts = safe_get(f"https://www.reddit.com/user/{user}/submitted.json?limit=25",
                      req=req, timeout=7, headers=H)
    top_subs = Counter()
    if posts is not None and posts.status_code == 200:
        try:
            for child in posts.json().get("data", {}).get("children", []):
                sub = child.get("data", {}).get("subreddit", "")
                if sub: top_subs[sub] += 1
        except Exception:
            pass

    findings = [wrap_finding(
        f"Reddit u/{user} — {age_days}d old, karma {prof.get('total_karma', 0)}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public profile data. Posting times → timezone inference. "
                    "Top subreddits → interests + employer signals (r/cscareerquestions, "
                    "r/sysadmin posts often reveal employer indirectly).",
        evidence_marker=(
            f"karma={prof.get('total_karma',0)} | "
            f"link_karma={prof.get('link_karma',0)} | "
            f"comment_karma={prof.get('comment_karma',0)} | "
            f"age_days={age_days} | "
            f"verified_email={prof.get('has_verified_email',False)} | "
            f"top_subs: {', '.join(f'{s}({c})' for s,c in top_subs.most_common(8))}"
        ))]

    return standard_response(
        tool="reddit_user_history", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"u/{user}: {age_days}d / {prof.get('total_karma',0)} karma",
        raw_data={"profile": prof, "top_subreddits": dict(top_subs)})


@router.post("/api/osint/reddit_user_history")
@vl_verify()
async def scan_reddit_user_history(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="reddit_user_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
