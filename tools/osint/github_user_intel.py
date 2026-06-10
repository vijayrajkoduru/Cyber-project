"""GitHub user intel — playbook §3 #45.

Public GitHub REST API (no token required for low-volume read). Returns
profile, public-repo count, follower count, public email if set, account
creation date, list of top languages. Useful for employee enum and
identity-pivot during pre-engagement recon.

Real probe — fetches actual public profile. Zero false positives. Rate
limit: 60 req/hour unauthenticated; if customer needs higher, they can
pass a PAT via auth_bearer.
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
    username = (req.target or "").strip().lstrip("@")
    if not username:
        return standard_response(
            tool="github_user_intel", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty username")

    headers = {"Accept": "application/vnd.github+json",
                "User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        headers["Authorization"] = f"Bearer {req.auth_bearer}"

    u = safe_get(f"https://api.github.com/users/{username}",
                  req=req, timeout=8, headers=headers)
    if u is None:
        return standard_response(
            tool="github_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="GitHub API unreachable")
    if u.status_code == 404:
        return standard_response(
            tool="github_user_intel", target=req.target,
            findings=[wrap_finding(
                f"GitHub user '{username}' does not exist",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public footprint — no remediation needed.",
                evidence_marker="HTTP 404 from /users/{username}")],
            tests_performed=1, vulnerable=False,
            tests_summary="Username free on GitHub")
    if u.status_code != 200:
        return standard_response(
            tool="github_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"GitHub API status {u.status_code} (likely rate-limited)")

    try:
        data = u.json()
    except Exception:
        return standard_response(
            tool="github_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    languages = []
    repos = safe_get(
        f"https://api.github.com/users/{username}/repos?per_page=30&sort=updated",
        req=req, timeout=8, headers=headers)
    if repos is not None and repos.status_code == 200:
        try:
            langs = Counter()
            for r in repos.json():
                lang = r.get("language")
                if lang:
                    langs[lang] += 1
            languages = [f"{l} ({c})" for l, c in langs.most_common(5)]
        except Exception:
            pass

    public_email = data.get("email")
    pii_findings = []
    if public_email:
        pii_findings.append(wrap_finding(
            f"PUBLIC email exposed in GitHub profile: {public_email}",
            severity="MEDIUM", cwe="CWE-359", cvss="5.3", owasp="A05:2021",
            remediation="If you don't want this email indexed by recruiters / "
                        "spammers / threat-actors, remove it from your GitHub "
                        "profile settings (Settings → Public profile → Email).",
            evidence_marker=f"profile.email = {public_email} (CONFIRMED via API)"))

    summary_evidence = (
        f"login={data.get('login')} | name={data.get('name') or '—'} | "
        f"company={data.get('company') or '—'} | "
        f"location={data.get('location') or '—'} | "
        f"public_repos={data.get('public_repos', 0)} | "
        f"followers={data.get('followers', 0)} | "
        f"created={data.get('created_at', '?')[:10]} | "
        f"top_langs={', '.join(languages) or '—'}"
    )

    findings = pii_findings + [wrap_finding(
        f"GitHub profile intel — {data.get('login')}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public profile data. For recon: cross-reference name + "
                    "company + email pattern guess + LinkedIn enum.",
        evidence_marker=summary_evidence)]

    return standard_response(
        tool="github_user_intel", target=req.target, findings=findings,
        tests_performed=2, vulnerable=bool(public_email),
        tests_summary=f"GitHub user profile + top languages ({len(languages)})",
        raw_data={"profile": data, "top_languages": languages})


@router.post("/api/osint/github_user_intel")
@vl_verify()
async def scan_github_user_intel(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="github_user_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
