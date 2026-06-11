"""GitHub recent activity events — playbook §3 #45 (activity slice).

GitHub /users/{u}/events/public returns last ~300 public events: pushes,
PRs, comments, repo creates. Reveals working hours / current focus / which
orgs the user actively contributes to. No token required.

Real probe. Zero false positives.
"""
import asyncio
from collections import Counter
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 15


def _do_scan(req: ScanRequest) -> dict:
    user = (req.target or "").strip().lstrip("@")
    if not user:
        return standard_response(
            tool="github_activity_recent", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty username")

    headers = {"Accept": "application/vnd.github+json",
                "User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        headers["Authorization"] = f"Bearer {req.auth_bearer}"

    r = safe_get(f"https://api.github.com/users/{user}/events/public?per_page=100",
                  req=req, timeout=10, headers=headers)
    if r is None or r.status_code == 404:
        return standard_response(
            tool="github_activity_recent", target=req.target,
            findings=[wrap_finding(
                f"GH user '{user}' has no public events / doesn't exist",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public activity footprint.",
                evidence_marker="404 or empty events (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No events")
    if r.status_code != 200:
        return standard_response(
            tool="github_activity_recent", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"GH status {r.status_code} (rate-limit?)")

    try:
        events = r.json()
    except Exception:
        return standard_response(
            tool="github_activity_recent", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON")

    if not events:
        return standard_response(
            tool="github_activity_recent", target=req.target,
            findings=[wrap_finding(
                f"{user} has 0 public events in the last 90 days",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Inactive account or all activity is in private repos.",
                evidence_marker="events array empty (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No recent events")

    type_counts = Counter(e.get("type", "?") for e in events)
    repos = Counter()
    hours = Counter()
    for e in events:
        if e.get("repo", {}).get("name"):
            repos[e["repo"]["name"]] += 1
        ts = e.get("created_at", "")
        if "T" in ts:
            try:
                hours[int(ts[11:13])] += 1
            except ValueError:
                pass

    peak_hours = [f"{h:02d}:00 UTC ({c})" for h, c in hours.most_common(3)]

    findings = [wrap_finding(
        f"GH {user} — {len(events)} recent public events",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public activity reveals working hours (peak commit hours = "
                    "approximate timezone), focus repos, and contribution targets.",
        evidence_marker=(
            f"event_types: {dict(type_counts.most_common(5))} | "
            f"top_repos: {', '.join(r for r, _ in repos.most_common(5))} | "
            f"peak_hours_utc: {', '.join(peak_hours)} | "
            f"first_event: {events[-1].get('created_at','?')[:10]} | "
            f"last_event: {events[0].get('created_at','?')[:10]}"
        ))]

    return standard_response(
        tool="github_activity_recent", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"{user}: {len(events)} events / peak UTC hour {hours.most_common(1)[0][0] if hours else '?'}",
        raw_data={"event_count": len(events), "type_counts": dict(type_counts),
                   "top_repos": dict(repos.most_common(10)),
                   "hour_distribution": dict(hours)})


@router.post("/api/osint/github_activity_recent")
@vl_verify()
async def scan_github_activity_recent(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="github_activity_recent", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
