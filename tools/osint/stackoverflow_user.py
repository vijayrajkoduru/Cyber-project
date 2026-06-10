"""Stack Overflow public user API — playbook §3 (developer-intel slice).

Stack Exchange v2.3 API exposes user profiles publicly with generous rate
limit (300/day per IP). Returns reputation, tags they answer in, account
age, location, website — strong tech-stack inference signal.

Target = numeric SO user ID (extract from profile URL: /users/12345/name).

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
    raw = (req.target or "").strip()
    m = re.search(r"(?:^|/)(\d{4,10})(?:/|$)", raw)
    user_id = m.group(1) if m else (raw if raw.isdigit() else None)
    if not user_id:
        return standard_response(
            tool="stackoverflow_user", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be SO user ID or profile URL")

    r = safe_get(
        f"https://api.stackexchange.com/2.3/users/{user_id}?site=stackoverflow",
        req=req, timeout=8, headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="stackoverflow_user", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"SO API status {r.status_code if r else 'no-conn'}")

    try:
        items = r.json().get("items", [])
    except Exception:
        return standard_response(
            tool="stackoverflow_user", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")
    if not items:
        return standard_response(
            tool="stackoverflow_user", target=req.target,
            findings=[wrap_finding(
                f"SO user {user_id} not found",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker="empty items[] (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not found")

    u = items[0]
    # Top tags
    tg = safe_get(
        f"https://api.stackexchange.com/2.3/users/{user_id}/top-tags?site=stackoverflow",
        req=req, timeout=6, headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    tags = []
    if tg is not None and tg.status_code == 200:
        try:
            tags = [t.get("tag_name") for t in tg.json().get("items", [])][:8]
        except Exception:
            pass

    findings = [wrap_finding(
        f"SO user — {u.get('display_name','?')} (rep {u.get('reputation',0):,})",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Strong tech-stack signal. Top answer tags → expertise areas. "
                    "Website link in profile → often personal blog with email + employer.",
        evidence_marker=(
            f"name={u.get('display_name','?')} | "
            f"rep={u.get('reputation',0)} | "
            f"location={u.get('location','?')} | "
            f"website={u.get('website_url','—')} | "
            f"created={u.get('creation_date',0)} | "
            f"top_tags={','.join(tags)}"
        ))]

    return standard_response(
        tool="stackoverflow_user", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"SO: {u.get('display_name','?')} rep {u.get('reputation',0)}",
        raw_data={"user": u, "top_tags": tags})


@router.post("/api/osint/stackoverflow_user")
@vl_verify()
async def scan_stackoverflow_user(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="stackoverflow_user", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
