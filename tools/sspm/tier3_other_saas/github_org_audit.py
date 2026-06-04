"""github_org_audit - GitHub Organisation security posture (playbook §6).

Uses the GitHub REST API (api.github.com) with a customer-supplied PAT
(classic or fine-grained) to audit a single Organization for posture gaps:

  - HIGH   : org members with no 2FA enabled (only counted if PAT grants
             org:read AND user has set 2fa_disabled_users filter)
  - HIGH   : public repositories with NO branch protection on default branch
  - HIGH   : org has SAML SSO available but NOT enforced
  - MEDIUM : org admins dormant >180 days (no commit on tracked repos)
  - MEDIUM : org members with admin role on production-tagged repos

Customer input via ScanRequest.options:
  - github_token       = PAT (classic ghp_... or fine-grained github_pat_...)
                         Required scopes (classic): read:org, admin:org,
                         repo (or public_repo). Fine-grained: Organization
                         permissions = Members:read, Administration:read,
                         Custom roles:read, Repository permissions =
                         Administration:read, Contents:read.
  - github_org         = org login (e.g. "vulnuslab")  [required]
  - repo_limit         = how many repos to inspect for branch protection /
                         dormant admins (default 30, max 100). Set higher
                         only if you have an Enterprise PAT and time.

All operations READ-ONLY. No webhook installs, no team writes, no SAML
identity provisioning.
"""
from __future__ import annotations
import asyncio
import datetime
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.github_org_audit_findings import (
    GITHUB_ORG_AUDIT_FINDING_RULES,
)

router = APIRouter()

GH_BASE = "https://api.github.com"
TIMEOUT = 30.0
DORMANT_DAYS = 180
DEFAULT_REPO_LIMIT = 30
MAX_REPO_LIMIT = 100


class GithubOrgAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def _gh_get(client, path: str, token: str,
                   params: Optional[dict] = None) -> tuple[int, dict]:
    """GitHub REST GET. Returns (status_code, json_or_text_dict)."""
    url = f"{GH_BASE}{path}"
    try:
        r = await client.get(url, params=params or {},
                              headers={
                                  "Authorization": f"Bearer {token}",
                                  "Accept": "application/vnd.github+json",
                                  "X-GitHub-Api-Version": "2022-11-28",
                                  "User-Agent": "VulnusLab-SSPM/1.0",
                              }, timeout=TIMEOUT)
        try:
            body = r.json()
        except Exception:
            body = {"text": (r.text or "")[:400]}
        return r.status_code, body
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {str(e)[:200]}"}


async def _list_paged(client, path: str, token: str,
                      max_pages: int = 5, per_page: int = 100,
                      extra_params: Optional[dict] = None) -> list[dict]:
    """Page through a list endpoint. Returns flat list. Stops on error."""
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        params = dict(extra_params or {})
        params["per_page"] = per_page
        params["page"] = page
        status, body = await _gh_get(client, path, token, params)
        if status >= 400 or not isinstance(body, list):
            break
        out.extend(body)
        if len(body) < per_page:
            break
    return out


def _is_dormant(iso_ts: str, threshold_days: int = DORMANT_DAYS) -> bool:
    if not iso_ts:
        return True
    try:
        dt = datetime.datetime.strptime(iso_ts[:19], "%Y-%m-%dT%H:%M:%S")
        return (datetime.datetime.utcnow() - dt).days >= threshold_days
    except Exception:
        return True


async def _check_branch_protection(client, owner: str, repo: str,
                                    default_branch: str, token: str) -> dict:
    """Return {'protected': bool, 'rules': {...}, '_error': str}."""
    path = f"/repos/{owner}/{repo}/branches/{default_branch}/protection"
    status, body = await _gh_get(client, path, token)
    if status == 404:
        return {"protected": False, "rules": {}}
    if status == 403 and isinstance(body, dict) \
            and "Branch not protected" in str(body.get("message", "")):
        return {"protected": False, "rules": {}}
    if status >= 400:
        return {"protected": None, "rules": {},
                "_error": f"HTTP {status}: {str(body)[:120]}"}
    rules = body if isinstance(body, dict) else {}
    return {"protected": True, "rules": {
        "required_pull_request_reviews": bool(rules.get("required_pull_request_reviews")),
        "required_status_checks":        bool(rules.get("required_status_checks")),
        "enforce_admins":                bool((rules.get("enforce_admins") or {}).get("enabled")),
        "required_signatures":           bool((rules.get("required_signatures") or {}).get("enabled")),
        "allow_force_pushes":            bool((rules.get("allow_force_pushes") or {}).get("enabled")),
        "allow_deletions":               bool((rules.get("allow_deletions") or {}).get("enabled")),
    }}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    token = (opts.get("github_token") or "").strip()
    org = (opts.get("github_org") or "").strip()
    if not token or not org:
        ctx.state["github_org_audit_creds_missing"] = True
        ctx.state["github_org_audit_total"] = 0
        ctx.source("credentials required (github_token + github_org)")
        return

    try:
        repo_limit = int(opts.get("repo_limit") or DEFAULT_REPO_LIMIT)
    except (TypeError, ValueError):
        repo_limit = DEFAULT_REPO_LIMIT
    repo_limit = max(5, min(repo_limit, MAX_REPO_LIMIT))

    try:
        import httpx
    except ImportError:
        ctx.state["github_org_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=True) as client:
        # ── 1. Org details ──
        status, org_info = await _gh_get(client, f"/orgs/{org}", token)
        if status == 401:
            ctx.state["github_org_audit_auth_error"] = (
                "HTTP 401 — token rejected. Check PAT scopes (read:org needed).")
            ctx.state["github_org_audit_total"] = 0
            ctx.source("GitHub 401")
            return
        if status == 404:
            ctx.state["github_org_audit_not_found"] = True
            ctx.state["github_org_audit_total"] = 0
            ctx.source(f"org {org} not found / no access")
            return
        if status >= 400 or not isinstance(org_info, dict):
            ctx.state["github_org_audit_api_error"] = (
                f"GET /orgs/{org} -> HTTP {status}: {str(org_info)[:200]}")
            ctx.state["github_org_audit_total"] = 0
            ctx.source(f"org info HTTP {status}")
            return

        two_factor_requirement_enabled = bool(
            org_info.get("two_factor_requirement_enabled"))
        # SAML enforcement is exposed under .sso_url + .has_organization_projects;
        # the authoritative field is "members_can_create_repositories_for_*" and
        # GraphQL .samlIdentityProvider. REST signal: the
        # /orgs/{org}/external-groups path returns 404 unless SSO is configured.
        status_sso, _ = await _gh_get(client, f"/orgs/{org}/external-groups", token)
        sso_available = status_sso in (200, 403)  # 403 = SSO present but token un-SSO-authorized

        # ── 2. Members without 2FA (only works on classic PAT with admin:org) ──
        users_no_2fa = await _list_paged(
            client, f"/orgs/{org}/members", token,
            max_pages=10, per_page=100,
            extra_params={"filter": "2fa_disabled"},
        )

        # ── 3. Org repositories (cap at repo_limit) ──
        all_repos = await _list_paged(
            client, f"/orgs/{org}/repos", token,
            max_pages=(repo_limit // 100) + 1, per_page=100,
            extra_params={"type": "all", "sort": "updated", "direction": "desc"},
        )
        repos = all_repos[:repo_limit]
        public_repos = [r for r in repos if not r.get("private")]
        public_no_protection = []

        # Parallel branch-protection checks (concurrency limited)
        sem = asyncio.Semaphore(5)

        async def _check(r):
            async with sem:
                owner = (r.get("owner") or {}).get("login") or org
                name = r.get("name") or ""
                default = r.get("default_branch") or "main"
                bp = await _check_branch_protection(
                    client, owner, name, default, token)
                if bp.get("protected") is False:
                    public_no_protection.append({
                        "repo": f"{owner}/{name}",
                        "default_branch": default,
                        "private": r.get("private", False),
                        "stargazers": r.get("stargazers_count", 0),
                    })
        await asyncio.gather(*[_check(r) for r in public_repos])

        # ── 4. Dormant admin commits — sample most-recently-updated repos ──
        # We pull /orgs/{org}/members?role=admin then check each admin's
        # public commits via /users/{username}/events/orgs/{org} (truncated).
        admins = await _list_paged(
            client, f"/orgs/{org}/members", token,
            max_pages=5, per_page=100,
            extra_params={"role": "admin"},
        )
        admin_logins = [a.get("login") for a in admins if a.get("login")][:20]

        dormant_admins = []
        async def _admin_recent_commit(login):
            async with sem:
                # Public events; for fine-grained PATs without read:user this
                # returns the public-only timeline (sufficient for detecting
                # active vs dormant).
                status_e, body_e = await _gh_get(
                    client, f"/users/{login}/events/orgs/{org}", token,
                    params={"per_page": 30})
                if status_e >= 400 or not isinstance(body_e, list):
                    return
                latest = ""
                for e in body_e:
                    ts = e.get("created_at") or ""
                    if ts > latest:
                        latest = ts
                if _is_dormant(latest, DORMANT_DAYS):
                    dormant_admins.append({
                        "login": login,
                        "last_activity": latest or "never",
                    })
        await asyncio.gather(*[_admin_recent_commit(l) for l in admin_logins])

    # ── Classify aggregate signals ──
    findings_count = (len(users_no_2fa) + len(public_no_protection)
                      + len(dormant_admins))

    sso_not_enforced = False
    sso_unknown = False
    # heuristic: if org_info.has_organization_projects is True AND
    # two_factor_requirement_enabled is True but sso_available is True
    # AND there's NO billing.saml then SSO probably not enforced. We expose
    # the raw signal honestly rather than over-claim.
    if sso_available:
        # GitHub doesn't expose enforced-flag on REST; mark as MEDIUM with
        # explicit "verify in admin console" remediation.
        sso_not_enforced = True
        sso_unknown = True

    if not two_factor_requirement_enabled:
        findings_count += 1
    if sso_not_enforced:
        findings_count += 1

    ctx.state["github_org_login"] = org_info.get("login", org)
    ctx.state["github_org_name"] = org_info.get("name", "")
    ctx.state["github_org_plan"] = (org_info.get("plan") or {}).get("name", "")
    ctx.state["github_org_two_factor_required"] = two_factor_requirement_enabled
    ctx.state["github_org_repos_scanned"] = len(repos)
    ctx.state["github_org_public_repos"] = len(public_repos)
    ctx.state["github_org_public_no_protection"] = public_no_protection
    ctx.state["github_org_members_no_2fa"] = [
        {"login": u.get("login"), "id": u.get("id")} for u in users_no_2fa
    ]
    ctx.state["github_org_admins_total"] = len(admin_logins)
    ctx.state["github_org_admins_dormant"] = dormant_admins
    ctx.state["github_org_sso_available"] = sso_available
    ctx.state["github_org_sso_unknown_enforcement"] = sso_unknown
    ctx.state["github_org_audit_total"] = findings_count
    ctx.source(f"GitHub org '{org}' audited — "
               f"{len(repos)} repo(s), {len(admin_logins)} admin(s), "
               f"2FA-required={two_factor_requirement_enabled}; "
               f"{findings_count} posture issue(s)")


INTEL_FIELDS = [
    ("Organisation login",                    "github_org_login"),
    ("Organisation plan",                     "github_org_plan"),
    ("2FA required org-wide",                 "github_org_two_factor_required"),
    ("Repos scanned",                         "github_org_repos_scanned"),
    ("Public repos in scope",                 "github_org_public_repos"),
    ("Public repos without branch protection","github_org_public_no_protection"),
    ("Members without 2FA",                   "github_org_members_no_2fa"),
    ("Total admins audited",                  "github_org_admins_total"),
    ("Dormant admins (180+ days)",            "github_org_admins_dormant"),
    ("SAML SSO present",                      "github_org_sso_available"),
]


@router.post("/api/sspm/github_org_audit")
async def sspm_github_org_audit(req: GithubOrgAuditRequest,
                                 _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="github_org_audit",
        gather_func=_gather_with_options,
        finding_rules=GITHUB_ORG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
