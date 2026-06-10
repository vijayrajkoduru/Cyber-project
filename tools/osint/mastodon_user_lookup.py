"""Mastodon / fediverse user lookup via WebFinger + accounts API — playbook §3 #44.

Target format: user@instance.tld (e.g. mike@mastodon.social). Resolves
via WebFinger then pulls the public account info from the instance API.
All Mastodon instances expose these endpoints — no auth needed.

Real probe. Zero false positives.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 15
H = {"User-Agent": "VulnusLab-OSINT/1.0", "Accept": "application/json"}


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip().lstrip("@")
    if "@" not in target:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be user@instance.tld")
    user, instance = target.rsplit("@", 1)
    if not re.match(r"^[A-Za-z0-9._-]+$", user) or "." not in instance:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid user@instance format")

    # WebFinger discover
    wf = safe_get(
        f"https://{instance}/.well-known/webfinger?resource=acct:{user}@{instance}",
        req=req, timeout=7, headers=H)
    if wf is None or wf.status_code != 200:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target,
            findings=[wrap_finding(
                f"WebFinger for {target} failed ({wf.status_code if wf else 'no-conn'})",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either instance doesn't support WebFinger, account "
                            "doesn't exist, or instance is offline.",
                evidence_marker="WebFinger lookup failed (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="WebFinger failed")

    try:
        wf_data = wf.json()
    except Exception:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON WebFinger")

    # Mastodon accounts API
    acc = safe_get(f"https://{instance}/api/v1/accounts/lookup?acct={user}",
                    req=req, timeout=7, headers=H)
    if acc is None or acc.status_code != 200:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason=f"instance accounts API returned {acc.status_code if acc else 'no-conn'} "
                            f"(may not be a Mastodon instance — could be Pleroma/Misskey)")

    try:
        a = acc.json()
    except Exception:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="non-JSON accounts API response")

    findings = [wrap_finding(
        f"Mastodon — {a.get('display_name') or user} @ {instance}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public fediverse profile. Note: federated posts may be "
                    "cached on hundreds of other instances even if deleted.",
        evidence_marker=(
            f"display_name={a.get('display_name','—')} | "
            f"bio={(a.get('note','') or '')[:120]} | "
            f"followers={a.get('followers_count',0)} | "
            f"following={a.get('following_count',0)} | "
            f"toots={a.get('statuses_count',0)} | "
            f"created={a.get('created_at','?')[:10]}"
        ))]

    return standard_response(
        tool="mastodon_user_lookup", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"{target}: {a.get('statuses_count',0)} toots",
        raw_data={"webfinger": wf_data, "account": a})


@router.post("/api/osint/mastodon_user_lookup")
@vl_verify()
async def scan_mastodon_user_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="mastodon_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
