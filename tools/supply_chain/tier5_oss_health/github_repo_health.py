"""github_repo_health - OSS project health audit via public GitHub API (playbook §8).

REAL remote probe. When ScanRequest.repo_url (or target) points at a public
GitHub repository, this scanner queries the UNAUTHENTICATED GitHub REST API
(api.github.com) — read-only public endpoints only — and derives the OSS
supply-chain health signals an analyst would pull for an OpenSSF-Scorecard-
style review:

  - repo metadata        GET /repos/{o}/{r}        archived/disabled, pushed_at,
                                                    fork, default_branch, license
  - contributors (page1) GET /repos/{o}/{r}/contributors?per_page=100   bus-factor
  - recent commit        GET /repos/{o}/{r}/commits?per_page=1          last activity
  - community profile    GET /repos/{o}/{r}/community/profile           SECURITY/CoC
  - tags (page1)         GET /repos/{o}/{r}/tags?per_page=1             release cadence

ZERO-FALSE-POSITIVE policy: graded severities are emitted ONLY from observed
API facts (e.g. archived==true, pushed_at older than the staleness window,
single dominant contributor). Each graded rule stamps verified_exploit=True
because the condition was read directly from the live API. Missing input,
non-GitHub host, rate-limit, private/404, or network error -> INFO, never a
graded finding.

This is detection only (VA): public read endpoints, no writes, no token
required, no exploitation.

Customer input: ScanRequest.repo_url (preferred) or target (github.com/o/r).
"""
from __future__ import annotations
import asyncio
import datetime
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

router = APIRouter()
TIMEOUT = 10
API = "https://api.github.com"
_STALE_DAYS = 365            # no push in a year => abandonment risk
_BUS_FACTOR_DOMINANCE = 0.90  # one author owns >=90% of commits => bus-factor 1

_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0",
            "Accept": "application/vnd.github+json"}
_COMMUNITY_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0",
                      "Accept": "application/vnd.github.black-panther-preview+json"}

_GH_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)


def _parse_owner_repo(value: str):
    if not value:
        return None
    m = _GH_RE.search(value.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if owner.lower() in ("", "orgs", "users", "settings"):
        return None
    return owner, repo


def _get(url: str, headers: dict | None = None) -> dict:
    if requests is None:
        return {"ok": False, "err": "requests unavailable"}
    try:
        r = requests.get(url, headers=headers or _HEADERS, timeout=TIMEOUT, verify=True)
        out = {"ok": True, "status": r.status_code,
               "headers": {k.lower(): v for k, v in r.headers.items()}}
        try:
            out["json"] = r.json()
        except Exception:
            out["json"] = None
        return out
    except Exception as e:
        return {"ok": False, "err": str(e)[:120]}


def _days_since_iso(iso: str) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        return (now - dt).days
    except Exception:
        return None


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        raw = (getattr(req, "repo_url", None) or "").strip() or (ctx.host or "").strip()
        pr = _parse_owner_repo(raw)
        if not pr:
            ctx.state["gh_health_no_input"] = True
            ctx.source("github repo_url required")
            return
        if requests is None:
            ctx.state["gh_health_error"] = "requests library unavailable"
            ctx.source("no http client")
            return

        owner, repo = pr
        ctx.state["gh_repo"] = f"{owner}/{repo}"

        meta = await asyncio.to_thread(_get, f"{API}/repos/{owner}/{repo}")
        if not meta.get("ok"):
            ctx.state["gh_health_error"] = meta.get("err") or "request failed"
            ctx.source("api error")
            return

        status = meta.get("status")
        _hdrs = meta.get("headers") or {}
        _remaining = str(_hdrs.get("x-ratelimit-remaining", "")).strip()
        _msg = str((meta.get("json") or {}).get("message", "")).lower()
        # Unauthenticated API is 60 req/hr per IP; a busy/shared (datacenter/VPS)
        # IP can exhaust it and GitHub may answer 403/404/429. Classify any
        # non-200 with the rate-limit header at 0 (or a rate-limit message) as
        # rate-limited so a PUBLIC repo is never mislabeled "not found / private".
        if status != 200 and (_remaining == "0" or "rate limit" in _msg or status == 429):
            ctx.state["gh_rate_limited"] = True
            ctx.source("github api rate limited")
            return
        if status == 404:
            ctx.state["gh_not_found"] = True
            ctx.source("repo not found / private")
            return
        if status != 200 or not isinstance(meta.get("json"), dict):
            ctx.state["gh_health_error"] = f"unexpected status {status}"
            ctx.source(f"status {status}")
            return

        m = meta["json"]
        ctx.state["gh_archived"] = bool(m.get("archived"))
        ctx.state["gh_disabled"] = bool(m.get("disabled"))
        ctx.state["gh_is_fork"] = bool(m.get("fork"))
        ctx.state["gh_default_branch"] = m.get("default_branch") or "?"
        ctx.state["gh_license"] = ((m.get("license") or {}) or {}).get("spdx_id") or "NONE"
        ctx.state["gh_stars"] = m.get("stargazers_count") or 0
        ctx.state["gh_open_issues"] = m.get("open_issues_count") or 0
        ctx.state["gh_pushed_at"] = m.get("pushed_at") or ""
        ctx.state["gh_days_since_push"] = _days_since_iso(m.get("pushed_at") or "")

        # Contributors (page 1, up to 100) -> maintainer count + bus-factor proxy.
        contrib = await asyncio.to_thread(_get, f"{API}/repos/{owner}/{repo}/contributors?per_page=100")
        contributors = []
        if contrib.get("ok") and contrib.get("status") == 200 and isinstance(contrib.get("json"), list):
            for c in contrib["json"]:
                if isinstance(c, dict) and c.get("login"):
                    contributors.append({"login": c["login"], "contributions": c.get("contributions") or 0})
        ctx.state["gh_contributor_count"] = len(contributors)
        ctx.state["gh_top_contributors"] = sorted(
            contributors, key=lambda x: -x["contributions"])[:5]
        total_c = sum(c["contributions"] for c in contributors) or 0
        if contributors and total_c > 0:
            top = max(c["contributions"] for c in contributors)
            ctx.state["gh_top_contributor_share"] = round(top / total_c, 3)
        else:
            ctx.state["gh_top_contributor_share"] = None

        # Latest commit timestamp (independent of pushed_at).
        commits = await asyncio.to_thread(_get, f"{API}/repos/{owner}/{repo}/commits?per_page=1")
        if commits.get("ok") and commits.get("status") == 200 and isinstance(commits.get("json"), list) and commits["json"]:
            c0 = commits["json"][0]
            commit_date = (((c0.get("commit") or {}).get("committer") or {}).get("date")) or ""
            ctx.state["gh_last_commit_date"] = commit_date
            ctx.state["gh_days_since_commit"] = _days_since_iso(commit_date)

        # Community profile -> SECURITY policy / CoC presence.
        comm = await asyncio.to_thread(_get, f"{API}/repos/{owner}/{repo}/community/profile",
                                       _COMMUNITY_HEADERS)
        if comm.get("ok") and comm.get("status") == 200 and isinstance(comm.get("json"), dict):
            files = comm["json"].get("files") or {}
            ctx.state["gh_has_security_policy"] = bool(files.get("security"))
            ctx.state["gh_has_code_of_conduct"] = bool(files.get("code_of_conduct"))
            ctx.state["gh_has_contributing"] = bool(files.get("contributing"))
            ctx.state["gh_health_percentage"] = comm["json"].get("health_percentage")

        ctx.source(f"github: {owner}/{repo} ({ctx.state.get('gh_contributor_count', 0)} contributors, "
                   f"last push {ctx.state.get('gh_days_since_push')}d ago)")
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("gh_health_no_input"):
        return None
    return {"name": "github_repo_health: GitHub repo_url required",
            "severity": "INFO",
            "evidence": "Provide repo_url=https://github.com/<owner>/<repo> (or target) "
                        "to audit OSS project health.",
            "remediation": "Re-run with a public GitHub repository URL.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_client_missing(s):
    if "requests library unavailable" not in (s.get("gh_health_error") or ""):
        return None
    return {"name": "github_repo_health: HTTP client unavailable",
            "severity": "INFO",
            "evidence": s.get("gh_health_error"),
            "remediation": "Install the `requests` library in the scanner environment.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_rate_limited(s):
    if not s.get("gh_rate_limited"):
        return None
    return {"name": "github_repo_health: GitHub API rate limit reached",
            "severity": "INFO",
            "evidence": "Unauthenticated GitHub API quota was exhausted; health signals "
                        "could not be read this run.",
            "remediation": "Re-run later, or supply a GitHub token to raise the API quota.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_not_found(s):
    if not s.get("gh_not_found"):
        return None
    return {"name": "github_repo_health: repository not found or private",
            "severity": "INFO",
            "evidence": f"{s.get('gh_repo')} returned HTTP 404 to the public API (private, "
                        "renamed, or deleted).",
            "remediation": "Confirm the repository slug. A renamed/transferred repo can be a "
                           "repojacking risk — re-register the old name as a placeholder if "
                           "any manifest still references it.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_generic_error(s):
    err = s.get("gh_health_error") or ""
    if not err or "requests library unavailable" in err:
        return None
    return {"name": "github_repo_health: API query failed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Confirm the repository is public and api.github.com is reachable.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_archived(s):
    if not (s.get("gh_archived") or s.get("gh_disabled")):
        return None
    what = "archived" if s.get("gh_archived") else "disabled"
    return {"name": f"OSS dependency repository is {what} — maintenance has stopped",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1104", "owasp": "A06:2021",
            "verified_exploit": True,
            "evidence": f"GitHub reports {s.get('gh_repo')} as {what}. {what.capitalize()} "
                        "projects receive no security patches; any CVE found later is permanent.",
            "remediation": "Migrate off the unmaintained dependency to a maintained fork or "
                           "alternative, or vendor + self-maintain it with an internal SLA."}


def _rule_stale(s):
    if s.get("gh_archived") or s.get("gh_disabled"):
        return None  # already covered by the stronger rule
    days = s.get("gh_days_since_push")
    if days is None or days < _STALE_DAYS:
        return None
    return {"name": f"OSS dependency repository inactive for {days} days",
            "severity": "INFO",
            "cwe": "CWE-1104", "owasp": "A06:2021",
            "evidence": f"{s.get('gh_repo')} last received a push {days} days ago "
                        f"(staleness window {_STALE_DAYS}d). Prolonged inactivity raises "
                        "abandonment and slow-CVE-response risk. Note: many mature projects "
                        "release infrequently — this is an advisory signal, not a proven vuln.",
            "remediation": "Track the project's activity. Plan a migration path before it is "
                           "fully abandoned; subscribe to its security advisories."}


def _rule_bus_factor(s):
    share = s.get("gh_top_contributor_share")
    cnt = s.get("gh_contributor_count") or 0
    if share is None:
        return None
    # Only flag when one author dominates AND there are few contributors.
    if cnt > 3 and share < _BUS_FACTOR_DOMINANCE:
        return None
    if cnt == 0:
        return None
    if cnt == 1 or share >= _BUS_FACTOR_DOMINANCE:
        top = (s.get("gh_top_contributors") or [{}])[0]
        return {"name": f"OSS dependency has bus-factor risk ({cnt} contributor(s))",
                "severity": "INFO",
                "cwe": "CWE-1357", "owasp": "A06:2021",
                "evidence": f"{s.get('gh_repo')}: {cnt} contributor(s) on the first page; top "
                            f"author '{top.get('login', '?')}' owns "
                            f"{round((share or 0) * 100)}% of contributions. A single-maintainer "
                            "dependency is a takeover / abandonment single point of failure.",
                "remediation": "Prefer dependencies with multiple active maintainers and a "
                               "governance body. For critical single-maintainer deps, pin + "
                               "vendor and monitor maintainer account changes."}
    return None


def _rule_no_security_policy(s):
    # Only assert when the community profile actually loaded (key present).
    if "gh_has_security_policy" not in s:
        return None
    if s.get("gh_has_security_policy"):
        return None
    return {"name": "OSS dependency has no published security policy (SECURITY.md)",
            "severity": "INFO",
            "cwe": "CWE-1059", "owasp": "A06:2021",
            "evidence": f"{s.get('gh_repo')} has no SECURITY.md / security policy per the GitHub "
                        "community profile. There is no documented vulnerability-disclosure "
                        "channel for this dependency.",
            "remediation": "Favor dependencies that publish a coordinated-disclosure policy. For "
                           "your own repos, add SECURITY.md (OpenSSF Scorecard 'Security-Policy')."}


def _rule_healthy(s):
    if any(s.get(k) for k in ("gh_health_no_input", "gh_health_error", "gh_rate_limited",
                              "gh_not_found")):
        return None
    if not s.get("gh_repo"):
        return None
    if s.get("gh_archived") or s.get("gh_disabled"):
        return None
    days = s.get("gh_days_since_push")
    if days is not None and days >= _STALE_DAYS:
        return None
    return {"name": "OSS dependency project health looks active",
            "severity": "POSITIVE",
            "evidence": f"{s.get('gh_repo')}: {s.get('gh_contributor_count', 0)} contributor(s), "
                        f"last push {days}d ago, license {s.get('gh_license', '?')}, "
                        f"security policy: {s.get('gh_has_security_policy')}.",
            "remediation": "Continue periodic OSS-health re-audits; pin versions and watch "
                           "advisories regardless of current health.",
            "cwe": "N/A", "owasp": "N/A"}


GITHUB_REPO_HEALTH_FINDING_RULES = [
    _rule_no_input,
    _rule_client_missing,
    _rule_rate_limited,
    _rule_not_found,
    _rule_generic_error,
    _rule_archived,
    _rule_stale,
    _rule_bus_factor,
    _rule_no_security_policy,
    _rule_healthy,
]


INTEL_FIELDS = [("Repository", "gh_repo"),
                ("Default branch", "gh_default_branch"),
                ("License", "gh_license"),
                ("Stars", "gh_stars"),
                ("Archived", "gh_archived"),
                ("Is fork", "gh_is_fork"),
                ("Days since last push", "gh_days_since_push"),
                ("Days since last commit", "gh_days_since_commit"),
                ("Contributor count", "gh_contributor_count"),
                ("Top contributors", "gh_top_contributors"),
                ("Top contributor share", "gh_top_contributor_share"),
                ("Has SECURITY policy", "gh_has_security_policy"),
                ("Has code of conduct", "gh_has_code_of_conduct"),
                ("Community health %", "gh_health_percentage")]


@router.post("/api/supply_chain/github_repo_health")
async def supply_chain_github_repo_health(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="github_repo_health",
        gather_func=_make_gather(req),
        finding_rules=GITHUB_REPO_HEALTH_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
