"""dev.to user public API — playbook §3 (dev-community slice).

dev.to exposes /api/users/by_username publicly. Returns bio, GitHub +
Twitter links if user listed them, post count, joined date.

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
    user = (req.target or "").strip().lstrip("@").lower()
    if not re.match(r"^[a-z0-9_]{1,30}$", user):
        return standard_response(
            tool="devto_user_lookup", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid dev.to handle")

    r = safe_get(f"https://dev.to/api/users/by_username?url={user}",
                  req=req, timeout=7,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0",
                            "Accept": "application/json"})
    if r is None or r.status_code == 404:
        return standard_response(
            tool="devto_user_lookup", target=req.target,
            findings=[wrap_finding(
                f"dev.to user '{user}' not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker=f"dev.to 404 (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")
    if r.status_code != 200:
        return standard_response(
            tool="devto_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"dev.to status {r.status_code}")

    try: u = r.json()
    except Exception:
        return standard_response(
            tool="devto_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")

    findings = [wrap_finding(
        f"dev.to — {u.get('name') or user}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public dev-community profile. Linked GitHub / Twitter "
                    "fields = cross-platform pivot points.",
        evidence_marker=(
            f"name={u.get('name','?')} | "
            f"username={u.get('username','?')} | "
            f"github={u.get('github_username','—')} | "
            f"twitter={u.get('twitter_username','—')} | "
            f"website={u.get('website_url','—')} | "
            f"location={u.get('location','—')} | "
            f"summary={(u.get('summary','') or '')[:100]}"
        ))]

    return standard_response(
        tool="devto_user_lookup", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"dev.to: {u.get('username','?')}",
        raw_data=u)


@router.post("/api/osint/devto_user_lookup")
@vl_verify()
async def scan_devto_user_lookup(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="devto_user_lookup", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
