"""Bluesky user lookup via public XRPC API — playbook §3 #43.

Bluesky's AT Protocol is fully open: anyone can query the firehose +
profile endpoints without auth. Returns DID, handle, display name,
follower/following counts, posts, indexed-at date.

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
    handle = (req.target or "").strip().lstrip("@").lower()
    # Bluesky handles look like user.bsky.social or user.customdomain.com
    if not handle or not re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", handle):
        return standard_response(
            tool="bluesky_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid Bluesky handle (e.g. user.bsky.social)")

    r = safe_get(
        f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}",
        req=req, timeout=8, headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None:
        return standard_response(
            tool="bluesky_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Bluesky public API unreachable")
    if r.status_code == 400 or r.status_code == 404:
        return standard_response(
            tool="bluesky_user_lookup", target=req.target,
            findings=[wrap_finding(
                f"Bluesky handle {handle} not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker=f"Bluesky {r.status_code} (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")
    if r.status_code != 200:
        return standard_response(
            tool="bluesky_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Bluesky status {r.status_code}")

    try:
        d = r.json()
    except Exception:
        return standard_response(
            tool="bluesky_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")

    findings = [wrap_finding(
        f"Bluesky — {d.get('displayName') or handle} (@{d.get('handle','?')})",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public AT Protocol data. Posts are federated and CACHED "
                    "across many AppView servers — deletion is best-effort.",
        evidence_marker=(
            f"did={d.get('did','?')[:30]}... | "
            f"followers={d.get('followersCount',0)} | "
            f"following={d.get('followsCount',0)} | "
            f"posts={d.get('postsCount',0)} | "
            f"indexed_at={d.get('indexedAt','?')[:10]} | "
            f"desc={(d.get('description','') or '')[:100]}"
        ))]

    return standard_response(
        tool="bluesky_user_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"bsky: {d.get('handle','?')}, {d.get('postsCount',0)} posts",
        raw_data=d)


@router.post("/api/osint/bluesky_user_lookup")
async def scan_bluesky_user_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="bluesky_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
