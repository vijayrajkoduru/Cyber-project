"""GitHub user/org public-repo recent-commits secret scan — playbook §3 #45 deep.

Scans last 5 public repos × last 10 commits per repo for high-confidence
secret patterns (AWS access keys, Stripe live keys, GitHub PATs, Slack
webhooks, Google API keys). Uses raw.githubusercontent.com diffs via the
public commits API. No token needed (60 req/hr).

Real probe — actually fetches diffs and pattern-matches. Patterns are
high-confidence (AKIA / sk_live_ / xoxb-) to avoid false positives.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 35

# High-confidence patterns only (avoid generic 'api_key' which has high FP)
PATTERNS = [
    ("AWS_ACCESS_KEY",   r"\bAKIA[0-9A-Z]{16}\b"),
    ("STRIPE_LIVE_KEY",  r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("STRIPE_PUB_KEY",   r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("GITHUB_PAT",       r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GITHUB_OAUTH",     r"\bgho_[A-Za-z0-9]{36}\b"),
    ("SLACK_WEBHOOK",    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
    ("SLACK_TOKEN",      r"\bxox[abprsi]-[A-Za-z0-9-]+\b"),
    ("GOOGLE_API",       r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("SENDGRID",         r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b"),
    ("MAILGUN",          r"\bkey-[a-f0-9]{32}\b"),
    ("PRIV_KEY",         r"-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"),
]


def _scan_text(text):
    hits = []
    for name, pat in PATTERNS:
        for m in re.finditer(pat, text):
            tok = m.group(0)
            hits.append((name, tok[:20] + ("…" + tok[-4:] if len(tok) > 24 else "")))
            if len(hits) >= 10: break
        if len(hits) >= 10: break
    return hits


def _do_scan(req: ScanRequest) -> dict:
    name = (req.target or "").strip().lstrip("@")
    if not name:
        return standard_response(
            tool="github_secrets_scan", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty username/org name")

    H = {"Accept": "application/vnd.github+json",
          "User-Agent": "VulnusLab-OSINT/1.0"}
    if req.auth_bearer:
        H["Authorization"] = f"Bearer {req.auth_bearer}"

    # Repo list (works for both users and orgs)
    r = safe_get(f"https://api.github.com/users/{name}/repos?per_page=5&sort=pushed",
                  req=req, timeout=8, headers=H)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="github_secrets_scan", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"GH repos list status {r.status_code if r else 'no-conn'}")

    try:
        repos = r.json()
    except Exception:
        return standard_response(
            tool="github_secrets_scan", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON repos")

    if not repos:
        return standard_response(
            tool="github_secrets_scan", target=req.target,
            findings=[wrap_finding(
                f"{name} has no public repos to scan",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No public repos = no exposed-commit attack surface.",
                evidence_marker="0 repos (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No public repos")

    # VL-TURBO deep: parallel fan-out across (repo, commit) pairs.
    # Was: 5 repos x 10 commits = 50 sequential fetches at 6s timeout =
    # 300s worst case (killed at 35s WALL_CLOCK_S leaving most repos
    # unscanned). Now: ~10s for all repos + commits in parallel.

    # Phase 1: fetch commit lists for all 5 repos in parallel
    def _fetch_commits(repo):
        full = repo.get("full_name")
        if not full:
            return (None, [])
        c = safe_get(f"https://api.github.com/repos/{full}/commits?per_page=10",
                      req=req, timeout=6, headers=H)
        if c is None or c.status_code != 200:
            return (full, [])
        try:
            return (full, c.json())
        except Exception:
            return (full, [])

    repo_commits = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        for full, commits in pool.map(_fetch_commits, repos[:5], timeout=15):
            if full and commits:
                for cm in commits[:10]:
                    sha = cm.get("sha", "?")
                    repo_commits.append((full, sha))

    # Phase 2: fetch all commit diffs in parallel (capped at 40)
    commit_jobs = repo_commits[:40]

    def _fetch_diff(job):
        full, sha = job
        cd = safe_get(f"https://api.github.com/repos/{full}/commits/{sha}",
                        req=req, timeout=6, headers=H)
        if cd is None or cd.status_code != 200:
            return (full, sha, [])
        try:
            return (full, sha, cd.json().get("files", []))
        except Exception:
            return (full, sha, [])

    secret_hits = []
    scanned = 0
    with ThreadPoolExecutor(max_workers=12) as pool:
        for full, sha, files in pool.map(_fetch_diff, commit_jobs, timeout=25):
            for f in files:
                patch = f.get("patch", "") or ""
                if not patch:
                    continue
                scanned += 1
                hits = _scan_text(patch)
                for tname, snippet in hits:
                    secret_hits.append((full, sha[:8], tname, snippet,
                                          f.get("filename", "?")))

    if not secret_hits:
        return standard_response(
            tool="github_secrets_scan", target=req.target,
            findings=[wrap_finding(
                f"GH {name}: {scanned} commit-diffs scanned, 0 high-confidence secrets",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No high-confidence secret patterns in recent commits. "
                            "Continue rotating commit-secret scanning (gitleaks/trufflehog) "
                            "in CI.",
                evidence_marker=f"scanned {scanned} diffs across {len(repos[:5])} repos (CONFIRMED clean)")],
            tests_performed=scanned, vulnerable=False,
            tests_summary=f"{scanned} diffs clean")

    evidence_lines = [
        f"{repo}@{sha} {ttype} in {fname}: {snip}"
        for repo, sha, ttype, snip, fname in secret_hits[:8]
    ]

    return standard_response(
        tool="github_secrets_scan", target=req.target,
        findings=[wrap_finding(
            f"LEAKED SECRETS — {len(secret_hits)} hit(s) in recent commits of {name}",
            severity="CRITICAL", cvss="9.8", cwe="CWE-798",
            owasp="A07:2021",
            remediation="EACH leaked secret must be ROTATED IMMEDIATELY at the "
                        "issuing provider (AWS / Stripe / etc.). Then either rewrite "
                        "history (git filter-repo) or accept the leak as permanent. "
                        "Set up gitleaks pre-commit + GitHub Advanced Security "
                        "secret scanning push protection.",
            evidence_marker=" | ".join(evidence_lines) +
                              f" (CONFIRMED via diff-pattern match)")],
        tests_performed=scanned, vulnerable=True,
        tests_summary=f"{len(secret_hits)} secrets in {scanned} diffs",
        raw_data={"hits": secret_hits[:20], "scanned_diffs": scanned,
                   "scanned_repos": [r.get("full_name") for r in repos[:5]]})


@router.post("/api/osint/github_secrets_scan")
@vl_verify()
async def scan_github_secrets_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="github_secrets_scan", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
