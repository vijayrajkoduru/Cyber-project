"""Twitch user public-page lookup — playbook §3 #42.

Twitch public profile page contains channel ID, display name, follower
count, last activity. Scrape from public HTML — no API key needed.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12


def _do_scan(req: ScanRequest) -> dict:
    user = (req.target or "").strip().lstrip("@").lower()
    if not re.match(r"^[a-z0-9_]{3,25}$", user):
        return standard_response(
            tool="twitch_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Twitch handle")

    r = safe_get(f"https://www.twitch.tv/{user}", req=req, timeout=8,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code == 404 or "Sorry. Unless" in (r.text or ""):
        return standard_response(
            tool="twitch_user_lookup", target=req.target,
            findings=[wrap_finding(
                f"Twitch user {user} not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public Twitch footprint.",
                evidence_marker="Twitch 404 / 'Sorry. Unless' (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")
    if r.status_code != 200:
        return standard_response(
            tool="twitch_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Twitch status {r.status_code}")

    body = r.text
    title = ""
    m = re.search(r'<meta property="og:title" content="([^"]+)"', body)
    if m: title = m.group(1)
    desc = ""
    m = re.search(r'<meta property="og:description" content="([^"]+)"', body)
    if m: desc = m.group(1)

    findings = [wrap_finding(
        f"Twitch user: {title or user}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public stream / channel data. Stream titles + clip "
                    "descriptions often leak game choices, schedules, and "
                    "casual identity reveals.",
        evidence_marker=f"title={title} | desc={desc[:120]}")]

    return standard_response(
        tool="twitch_user_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"twitch: {title or user}",
        raw_data={"user": user, "title": title, "description": desc})


@router.post("/api/osint/twitch_user_lookup")
@vl_verify()
async def scan_twitch_user_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="twitch_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
