"""ossf_scorecard_audit - OpenSSF Scorecard audit of a public GitHub repo (playbook §8 #97).

REAL remote probe. When ScanRequest.repo_url (or target) points at a public
GitHub repository, this scanner runs the OpenSSF Scorecard CLI
(https://github.com/ossf/scorecard) against it and surfaces the supply-chain
hygiene signals an analyst would pull for a dependency review:

  - aggregate score (0-10) across all Scorecard probes
  - per-check scores (-1 = not run / inconclusive, 0-10 otherwise)
  - high-impact checks that are failing (Branch-Protection, Token-Permissions,
    Dangerous-Workflow, Pinned-Dependencies, Signed-Releases, Code-Review)

Scorecard talks to the GitHub API and REQUIRES a GitHub token. The token is
read from GITHUB_AUTH_TOKEN (preferred) or GITHUB_TOKEN and passed to the
subprocess via env only. If no token is set, the scan degrades gracefully to
an INFO finding (not a gap, not a failure).

ZERO-FALSE-POSITIVE policy: graded severities (capped at MEDIUM) are emitted
ONLY from real Scorecard output (the aggregate score / per-check scores read
directly from the CLI JSON). Each graded rule stamps verified_exploit=True.
Missing input, missing binary, missing token, subprocess/JSON errors -> INFO,
never a graded finding.

This is detection only (VA): read-only CLI invocation, no writes, no
exploitation, no chaining.

Customer input: ScanRequest.repo_url (preferred) or target (github.com/o/r).
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()
SCORECARD_BIN = shutil.which("scorecard") or "/usr/local/bin/scorecard"
TIMEOUT = 300

# Scorecard scores are 0..10 (or -1 == not run / inconclusive).
_FAIL_MAX = 4.0       # a check scoring 0..4 (of 10) is "failing"
_AGG_MEDIUM_MAX = 5.0  # aggregate < 5.0 -> MEDIUM
_AGG_LOW_MAX = 7.0     # aggregate 5.0..6.9 -> LOW
_AGG_HEALTHY_MIN = 8.0  # aggregate >= 8.0 -> POSITIVE
_CRITICAL_CHECK_MAX = 2  # high-impact checks scoring <=2 are surfaced

# High-impact Scorecard checks whose failure most directly raises supply-chain
# risk. Names match the Scorecard CLI "checks[].name" field exactly.
_HIGH_IMPACT_CHECKS = {
    "Branch-Protection",
    "Token-Permissions",
    "Dangerous-Workflow",
    "Pinned-Dependencies",
    "Signed-Releases",
    "Code-Review",
}

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


def _parse_scorecard(data):
    """Scorecard --format=json emits a single object with top-level `score`
    (0-10 aggregate) and `checks` (list of {name, score, reason, details}).

    Returns (aggregate, checks[], failing[], high_impact_failing[]).
      aggregate          — float aggregate score, or None if absent
      checks             — [{name, score, reason}] for every reported check
      failing            — checks scoring 0..4 (excluding -1 == not run)
      high_impact_failing — high-impact checks scoring <=2 (excluding -1)
    """
    if not isinstance(data, dict):
        return None, [], [], []
    raw = data.get("score")
    try:
        aggregate = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        aggregate = None

    checks = []
    failing = []
    high_impact_failing = []
    for c in (data.get("checks") or []):
        if not isinstance(c, dict):
            continue
        name = c.get("name") or "?"
        try:
            score = float(c.get("score")) if c.get("score") is not None else -1.0
        except (TypeError, ValueError):
            score = -1.0
        reason = (c.get("reason") or "")[:200]
        entry = {"name": name, "score": score, "reason": reason}
        checks.append(entry)
        # -1 means "not run / inconclusive" -> never counted as a failure.
        if score == -1.0:
            continue
        if score <= _FAIL_MAX:
            failing.append(entry)
        if name in _HIGH_IMPACT_CHECKS and score <= _CRITICAL_CHECK_MAX:
            high_impact_failing.append(entry)
    return aggregate, checks, failing, high_impact_failing


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        raw = (getattr(req, "repo_url", None) or "").strip() or (ctx.host or "").strip()
        pr = _parse_owner_repo(raw)
        if not pr:
            ctx.state["ossf_no_input"] = True
            ctx.source("github repo_url required")
            return
        owner, repo = pr
        ctx.state["ossf_repo"] = f"{owner}/{repo}"

        if not (shutil.which("scorecard") or os.path.exists(SCORECARD_BIN)):
            ctx.state["ossf_binary_missing"] = True
            ctx.source("scorecard missing")
            return

        token = os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            ctx.state["ossf_no_token"] = True
            ctx.source("no github token")
            return
        ctx.state["ossf_token_used"] = True

        cmd = [SCORECARD_BIN, f"--repo={owner}/{repo}",
               "--format=json", "--show-details"]
        env = dict(os.environ, GITHUB_AUTH_TOKEN=token)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                ctx.state["ossf_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except Exception as e:
            ctx.state["ossf_error"] = f"subprocess: {str(e)[:120]}"
            ctx.source("subprocess failed")
            return

        if not stdout:
            err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            ctx.state["ossf_error"] = f"scorecard rc={proc.returncode}: {err_text}"
            ctx.source(f"scorecard rc={proc.returncode}")
            return

        # Scorecard prints a JSON object; tolerate any non-JSON preamble lines
        # by isolating the first '{' .. last '}' span.
        text = stdout.decode("utf-8", errors="ignore")
        try:
            data = json.loads(text)
        except Exception:
            lo, hi = text.find("{"), text.rfind("}")
            if lo == -1 or hi == -1 or hi <= lo:
                ctx.state["ossf_error"] = "scorecard output was not JSON"
                ctx.source("bad json")
                return
            try:
                data = json.loads(text[lo:hi + 1])
            except Exception as e:
                ctx.state["ossf_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

        aggregate, checks, failing, high_impact_failing = _parse_scorecard(data)
        if aggregate is None and not checks:
            ctx.state["ossf_error"] = "scorecard returned no score/checks"
            ctx.source("empty scorecard")
            return

        ctx.state["ossf_aggregate"] = aggregate
        ctx.state["ossf_checks_run"] = len([c for c in checks if c["score"] != -1.0])
        ctx.state["ossf_check_scores"] = [
            {"name": c["name"], "score": c["score"]} for c in checks
        ]
        ctx.state["ossf_failing_checks"] = failing
        ctx.state["ossf_failing_count"] = len(failing)
        ctx.state["ossf_high_impact_failing"] = high_impact_failing
        ctx.source(f"scorecard: {owner}/{repo} aggregate="
                   f"{aggregate if aggregate is not None else '?'}/10, "
                   f"{len(failing)} failing check(s)")
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("ossf_no_input"):
        return None
    return {"name": "ossf_scorecard_audit: GitHub repo_url required",
            "severity": "INFO",
            "evidence": "Provide repo_url=https://github.com/<owner>/<repo> (or target) "
                        "to run an OpenSSF Scorecard audit.",
            "remediation": "Re-run with a public GitHub repository URL.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_binary_missing(s):
    if not s.get("ossf_binary_missing"):
        return None
    return {"name": "ossf_scorecard_audit: OpenSSF Scorecard binary not installed",
            "severity": "INFO",
            "evidence": "The `scorecard` CLI was not found on PATH or at "
                        "/usr/local/bin/scorecard, so the OpenSSF Scorecard audit "
                        "was skipped for "
                        f"{s.get('ossf_repo') or 'the requested repository'}.",
            "remediation": "Install the OpenSSF Scorecard CLI "
                           "(https://github.com/ossf/scorecard) in the scanner "
                           "environment to enable this audit.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_no_token(s):
    if not s.get("ossf_no_token"):
        return None
    return {"name": "ossf_scorecard_audit: OpenSSF Scorecard needs a GitHub token "
                    "(set GITHUB_AUTH_TOKEN) - skipped",
            "severity": "INFO",
            "evidence": "OpenSSF Scorecard queries the GitHub API and requires a token. "
                        "Neither GITHUB_AUTH_TOKEN nor GITHUB_TOKEN is set in the scanner "
                        "environment, so the audit for "
                        f"{s.get('ossf_repo') or 'the requested repository'} was skipped.",
            "remediation": "Set GITHUB_AUTH_TOKEN (a read-only public_repo / fine-grained "
                           "token is sufficient) and re-run to obtain the Scorecard report.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_error(s):
    err = s.get("ossf_error") or ""
    if not err:
        return None
    return {"name": "ossf_scorecard_audit: OpenSSF Scorecard run failed",
            "severity": "INFO",
            "evidence": f"{s.get('ossf_repo') or 'repository'}: {err}",
            "remediation": "Confirm the repository is public, the GitHub token is valid, "
                           "and api.github.com is reachable, then re-run.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_low_aggregate(s):
    agg = s.get("ossf_aggregate")
    if agg is None:
        return None
    if agg >= _AGG_LOW_MAX:
        return None
    failing = s.get("ossf_failing_count") or 0
    if agg < _AGG_MEDIUM_MAX:
        severity, cvss = "MEDIUM", "5.3"
    else:
        severity, cvss = "LOW", "3.7"
    return {"name": f"OpenSSF Scorecard aggregate score low ({agg:.1f}/10)",
            "severity": severity, "cvss": cvss,
            "cwe": "CWE-1357", "owasp": "A06:2021",
            "verified_exploit": True,
            "evidence": f"{s.get('ossf_repo')}: OpenSSF Scorecard aggregate score is "
                        f"{agg:.1f}/10 with {failing} failing check(s). A low aggregate "
                        "indicates weak supply-chain security hygiene for this dependency.",
            "remediation": "Review the failing Scorecard checks (branch protection, token "
                           "permissions, dependency pinning, signed releases, code review) and "
                           "remediate them in the upstream project, or treat this dependency as "
                           "higher-risk: pin + vendor it and monitor its advisories."}


def _rule_critical_checks_failing(s):
    hi = s.get("ossf_high_impact_failing") or []
    if not hi:
        return None
    names = ", ".join(c["name"] for c in hi)
    detail = "; ".join(
        f"{c['name']} (score {c['score']:.0f}/10): {c['reason']}" if c.get("reason")
        else f"{c['name']} (score {c['score']:.0f}/10)"
        for c in hi
    )
    return {"name": f"OpenSSF Scorecard high-impact checks failing ({names})",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-1357", "owasp": "A08:2021",
            "verified_exploit": True,
            "evidence": f"{s.get('ossf_repo')}: high-impact OpenSSF Scorecard checks scored "
                        f"<= {_CRITICAL_CHECK_MAX}/10 — {detail}.",
            "remediation": "Address each failing high-impact check upstream: enable branch "
                           "protection, scope GITHUB_TOKEN permissions, remove dangerous "
                           "workflow patterns, pin dependencies by hash, sign releases, and "
                           "enforce code review. For third-party deps, weigh these gaps in "
                           "your dependency-selection and pinning decisions."}


def _rule_healthy(s):
    if any(s.get(k) for k in ("ossf_no_input", "ossf_binary_missing",
                              "ossf_no_token", "ossf_error")):
        return None
    agg = s.get("ossf_aggregate")
    if agg is None or agg < _AGG_HEALTHY_MIN:
        return None
    return {"name": f"OpenSSF Scorecard healthy ({agg:.1f}/10)",
            "severity": "POSITIVE",
            "evidence": f"{s.get('ossf_repo')}: OpenSSF Scorecard aggregate score is "
                        f"{agg:.1f}/10 across {s.get('ossf_checks_run', 0)} check(s) — strong "
                        "supply-chain security hygiene for this dependency.",
            "remediation": "Continue periodic Scorecard re-audits; pin versions and watch "
                           "advisories regardless of current score.",
            "cwe": "N/A", "owasp": "N/A"}


OSSF_SCORECARD_AUDIT_FINDING_RULES = [
    _rule_no_input,
    _rule_binary_missing,
    _rule_no_token,
    _rule_error,
    _rule_low_aggregate,
    _rule_critical_checks_failing,
    _rule_healthy,
]


INTEL_FIELDS = [("Repository", "ossf_repo"),
                ("Aggregate score", "ossf_aggregate"),
                ("Checks run", "ossf_checks_run"),
                ("Failing checks", "ossf_failing_count"),
                ("Failing check detail", "ossf_failing_checks"),
                ("High-impact failing", "ossf_high_impact_failing"),
                ("Per-check scores", "ossf_check_scores"),
                ("Token used", "ossf_token_used")]


@router.post("/api/supply_chain/ossf_scorecard_audit")
async def supply_chain_ossf_scorecard_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ossf_scorecard_audit",
        gather_func=_make_gather(req),
        finding_rules=OSSF_SCORECARD_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
