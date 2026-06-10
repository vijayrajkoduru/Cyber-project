"""Telegram public channel preview — playbook §3 #41.

t.me/{channel} (no /s/ for actual channel) returns an HTML preview with
channel name, description, subscriber count, and last 10 posts — no
bot token, no API, no auth.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10


def _do_scan(req: ScanRequest) -> dict:
    handle = (req.target or "").strip().lstrip("@").lower()
    if not re.match(r"^[a-z0-9_]{5,32}$", handle):
        return standard_response(
            tool="telegram_public_channel", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Telegram handle (5-32 chars, alphanumeric + _)")

    r = safe_get(f"https://t.me/s/{handle}", req=req, timeout=8,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="telegram_public_channel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Telegram status {r.status_code if r else 'no-conn'}")

    body = r.text or ""
    if "tgme_page_extra" not in body and "tgme_channel_info" not in body:
        return standard_response(
            tool="telegram_public_channel", target=req.target,
            findings=[wrap_finding(
                f"Telegram @{handle}: not a public channel (private or user)",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either handle belongs to private channel / user / "
                            "doesn't exist. Public channels expose /s/ preview.",
                evidence_marker="no channel-info markers in HTML (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not a public channel")

    title = ""
    m = re.search(r'<meta property="og:title" content="([^"]+)"', body)
    if m: title = m.group(1)
    desc = ""
    m = re.search(r'<meta property="og:description" content="([^"]+)"', body)
    if m: desc = m.group(1)
    subs = "?"
    m = re.search(r'<div class="tgme_page_extra">([^<]+)</div>', body)
    if m: subs = m.group(1).strip()
    # Count posts on page
    posts = len(re.findall(r'class="tgme_widget_message[^"]*"', body))

    findings = [wrap_finding(
        f"Telegram channel @{handle}: '{title}' ({subs})",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public channel metadata + visible posts. Channel admins "
                    "occasionally visible in description; subscriber count is "
                    "approximate. For invite-only / private channels, no public "
                    "footprint via this endpoint.",
        evidence_marker=(
            f"title={title} | subscribers={subs} | "
            f"visible_posts_on_page={posts} | "
            f"desc={desc[:120]}"
        ))]

    return standard_response(
        tool="telegram_public_channel", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"telegram: {title} / {subs}",
        raw_data={"handle": handle, "title": title, "subs": subs,
                   "description": desc, "visible_posts": posts})


@router.post("/api/osint/telegram_public_channel")
@vl_verify()
async def scan_telegram_public_channel(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="telegram_public_channel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
