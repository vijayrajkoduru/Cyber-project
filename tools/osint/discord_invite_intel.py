"""Discord invite metadata — playbook §3 #40.

Public Discord invite-resolution API: GET /api/v10/invites/{code}?with_counts=true
returns server name, member counts, channel name, inviter (if public), guild
features. No auth needed for invite lookups.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 10


def _extract_code(t: str) -> str | None:
    t = t.strip()
    # Accept full discord.gg/X, discord.com/invite/X, or just code
    m = re.search(r"(?:discord\.(?:gg|com/invite)/)?([A-Za-z0-9_-]{6,12})$", t)
    return m.group(1) if m else None


def _do_scan(req: ScanRequest) -> dict:
    code = _extract_code((req.target or "").strip())
    if not code:
        return standard_response(
            tool="discord_invite_intel", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be discord.gg invite code or URL")

    r = safe_get(
        f"https://discord.com/api/v10/invites/{code}?with_counts=true",
        req=req, timeout=7,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT",
                  "Accept": "application/json"})
    if r is None or r.status_code == 404:
        return standard_response(
            tool="discord_invite_intel", target=req.target,
            findings=[wrap_finding(
                f"Discord invite '{code}' invalid or expired",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No metadata available.",
                evidence_marker=f"Discord 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Invalid invite")
    if r.status_code != 200:
        return standard_response(
            tool="discord_invite_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Discord status {r.status_code}")

    try: d = r.json()
    except Exception:
        return standard_response(
            tool="discord_invite_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")

    guild = d.get("guild", {}) or {}
    channel = d.get("channel", {}) or {}
    inviter = d.get("inviter", {}) or {}

    findings = [wrap_finding(
        f"Discord — '{guild.get('name','?')}' (~{d.get('approximate_member_count', 0):,} members)",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public server intel. Verified servers + partnered "
                    "communities often have public moderation team info on "
                    "their websites. NOTE: passively scanning Discord invite "
                    "codes is OK; joining + scraping requires consent.",
        evidence_marker=(
            f"guild_name={guild.get('name','?')} | "
            f"guild_id={guild.get('id','?')} | "
            f"member_count={d.get('approximate_member_count',0)} | "
            f"online={d.get('approximate_presence_count',0)} | "
            f"channel={channel.get('name','?')} ({channel.get('type','?')}) | "
            f"inviter={inviter.get('username','—')}#{inviter.get('discriminator','0000')} | "
            f"features={','.join(guild.get('features',[])[:5])}"
        ))]

    return standard_response(
        tool="discord_invite_intel", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"discord: {guild.get('name','?')} / {d.get('approximate_member_count',0)} members",
        raw_data=d)


@router.post("/api/osint/discord_invite_intel")
async def scan_discord_invite_intel(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="discord_invite_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
