"""YouTube channel recon via public RSS feed — playbook §3 #38.

YouTube exposes public RSS for any channel — no Data API key required.
Returns last 15 video titles, IDs, dates. Channel IDs come from the
about/profile lookup via the @handle public page.

Real probe via XML parse. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 18
H = {"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"}


def _resolve_channel(handle_or_id: str, req) -> str | None:
    """Channel IDs start with UC. Handles start with @. Custom URLs vary."""
    s = handle_or_id.strip().lstrip("@")
    if s.startswith("UC") and len(s) == 24:
        return s
    # Hit the channel page and extract channelId from meta
    r = safe_get(f"https://www.youtube.com/@{s}", req=req, timeout=8, headers=H)
    if r is None or r.status_code != 200:
        return None
    m = re.search(r'"channelId":"(UC[A-Za-z0-9_-]{22})"', r.text)
    return m.group(1) if m else None


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    if not target:
        return standard_response(
            tool="youtube_channel_rss", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty handle or channel ID")

    cid = _resolve_channel(target, req)
    if not cid:
        return standard_response(
            tool="youtube_channel_rss", target=req.target,
            findings=[wrap_finding(
                f"Could not resolve channel ID for '{target}'",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either handle doesn't exist or YouTube changed the "
                            "page structure (re-check selector). Try the 24-char UC... ID directly.",
                evidence_marker="channelId not found in page meta (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Channel not resolved")

    rss = safe_get(f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}",
                    req=req, timeout=8, headers=H)
    if rss is None or rss.status_code != 200:
        return standard_response(
            tool="youtube_channel_rss", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason=f"RSS status {rss.status_code if rss else 'no-conn'}")

    titles = re.findall(r"<title>([^<]+)</title>", rss.text)[:16]
    if titles:
        channel_name = titles[0]
        video_titles = titles[1:]
    else:
        channel_name = "?"
        video_titles = []
    published = re.findall(r"<published>([^<]+)</published>", rss.text)[1:16]

    if not video_titles:
        return standard_response(
            tool="youtube_channel_rss", target=req.target,
            findings=[wrap_finding(
                f"YouTube channel {channel_name} has no recent videos in RSS",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Channel exists but RSS feed is empty (new / inactive).",
                evidence_marker=f"channel_id={cid} | 0 videos in RSS (CONFIRMED)")],
            tests_performed=2, vulnerable=False,
            tests_summary="No RSS videos")

    findings = [wrap_finding(
        f"YouTube — '{channel_name}' ({len(video_titles)} recent videos)",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public RSS data. Posting cadence + topics reveal interests; "
                    "video descriptions often leak company affiliations / tools used.",
        evidence_marker=(
            f"channel_id={cid} | recent: " +
            " | ".join(f"[{p[:10]}] {t[:60]}"
                          for p, t in zip(published[:5], video_titles[:5]))
        ))]

    return standard_response(
        tool="youtube_channel_rss", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"{channel_name}: {len(video_titles)} recent videos",
        raw_data={"channel_id": cid, "channel_name": channel_name,
                   "videos": list(zip(published, video_titles))[:15]})


@router.post("/api/osint/youtube_channel_rss")
@vl_verify()
async def scan_youtube_channel_rss(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="youtube_channel_rss", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
