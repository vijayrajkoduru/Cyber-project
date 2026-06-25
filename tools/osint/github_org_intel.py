"""GitHub organization intel — playbook §3 #45 (org variant).

Public GitHub Orgs API. Returns org profile + member count + public repo
count + top members (visible only if their org membership is public).
Useful for mapping company tech-stack and identifying engineering staff
during pre-engagement recon.

Real probe, no token required (60 req/hr unauthenticated). Zero false
positives.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 15


def _do_scan(req: ScanRequest) -> dict:
    org = (req.target or "").strip().lstrip("@")
    if not org:
        return standard_response(
            tool="github_org_intel", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty org name")

    headers = {"Accept": "application/vnd.github+json",
                "User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        headers["Authorization"] = f"Bearer {req.auth_bearer}"

    o = safe_get(f"https://api.github.com/orgs/{org}",
                  req=req, timeout=8, headers=headers)
    if o is None or o.status_code == 404:
        return standard_response(
            tool="github_org_intel", target=req.target,
            findings=[wrap_finding(
                f"GitHub org '{org}' does not exist or is private",
                severity=grade.protective(), cwe="CWE-200",
                remediation="No public footprint.",
                evidence_marker="HTTP 404 from /orgs/{org}")],
            tests_performed=1, vulnerable=False,
            tests_summary="Org not found on GitHub")
    if o.status_code != 200:
        return standard_response(
            tool="github_org_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"GitHub status {o.status_code} (rate-limit?)")

    try:
        data = o.json()
    except Exception:
        return standard_response(
            tool="github_org_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON response")

    public_members = []
    m = safe_get(
        f"https://api.github.com/orgs/{org}/public_members?per_page=30",
        req=req, timeout=8, headers=headers)
    if m is not None and m.status_code == 200:
        try:
            public_members = [u.get("login") for u in m.json() if u.get("login")][:30]
        except Exception:
            pass

    findings = [wrap_finding(
        f"GitHub org intel — {data.get('login')}",
        severity=grade.info(), cwe="CWE-200",
        remediation="Public org data. Each public member is a recon pivot "
                    "(github_user_intel + email_pattern_guess + LinkedIn).",
        evidence_marker=(
            f"login={data.get('login')} | name={data.get('name') or '—'} | "
            f"public_repos={data.get('public_repos', 0)} | "
            f"public_members_shown={len(public_members)} | "
            f"members={', '.join(public_members[:10])}"
            + (' ...' if len(public_members) > 10 else '')
        ))]

    if data.get("email"):
        findings.insert(0, wrap_finding(
            f"Org-level email exposed in GitHub profile: {data.get('email')}",
            severity=grade.inventory(), cwe="CWE-359",
            remediation="Most orgs intentionally publish a contact email; "
                        "expected for security@/abuse@ but review if it's a personal alias.",
            evidence_marker=f"orgs/{org} email field = {data.get('email')} (CONFIRMED)"))

    return standard_response(
        tool="github_org_intel", target=req.target, findings=findings,
        tests_performed=2, vulnerable=False,
        tests_summary=f"GitHub org + {len(public_members)} public members",
        raw_data={"org": data, "public_members": public_members})


@router.post("/api/osint/github_org_intel")
@vl_verify()
async def scan_github_org_intel(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="github_org_intel", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
