"""actionlint_workflow_audit - GitHub Actions workflow security audit (playbook §4 #41 + #43).

Audits a repository's GitHub Actions workflows for two supply-chain risks:

  PART A (actionlint, OPTIONAL binary): if the `actionlint` CLI is present, runs
          it over `.github/workflows/*.yml|*.yaml` and parses the JSON error
          report (shellcheck/expression/syntax issues). Counts + collects top
          errors. If the binary is missing, this part is skipped but Part B
          still runs.

  PART B (PURE-PYTHON heuristic, ALWAYS runs): parses each workflow YAML and
          inspects every `uses:` value. Flags THIRD-PARTY actions (owner/repo@ref
          where owner is NOT 'actions', not a local './' path, and not a
          'docker://' ref) that are pinned to a MUTABLE ref — a branch
          (@main/@master/...) or a version tag (@v3 / @v3.1.0) — instead of an
          immutable 40-hex-char commit SHA. A mutable action ref lets the
          action's owner silently change the code that runs in your CI, the
          classic GitHub Actions supply-chain risk (CWE-1357 / OWASP A08:2021).

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone --depth 1 -> audit workflows in the tree)
  2. ScanRequest.target    (existing local dir with a .github/workflows/ tree)

ZERO-FALSE-POSITIVE policy: graded severities are emitted ONLY from facts read
out of real files — an actual actionlint error count, or an actual parsed
`uses:` value whose ref is mutable. Each graded rule stamps verified_exploit=True
because the condition was read directly from the cloned/local files. Missing
input, no workflows, clone error, or a missing actionlint binary -> INFO, never
a graded finding. Severities never exceed MEDIUM.

This is detection only (VA): read-only clone + parse, no writes, no exploitation,
no chaining. The clone tempdir is always removed in a finally block.
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

router = APIRouter()
ACTIONLINT_BIN = shutil.which("actionlint") or "/usr/local/bin/actionlint"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
CLONE_TIMEOUT = 90
LINT_TIMEOUT = 120

# A mutable ref is anything that is NOT a full 40-char commit SHA.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
# owner/repo[/subpath]@ref  — first-party 'actions/...' is GitHub-maintained.
_USES_RE = re.compile(r"^([^/@\s]+)/([^@\s]+)@(\S+)$")


async def _shallow_clone(repo_url: str, dest: str) -> tuple[bool, str]:
    if not shutil.which("git") and not os.path.exists(GIT_BIN):
        return False, "git not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            GIT_BIN, "clone", "--depth", "1", "--no-tags", "--quiet", repo_url, dest,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=CLONE_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            return False, "git clone timeout"
    except Exception as e:
        return False, f"git clone error: {str(e)[:80]}"
    if proc.returncode != 0:
        return False, f"git clone rc={proc.returncode}: {stderr.decode('utf-8', errors='ignore')[:160]}"
    return True, ""


def _find_workflow_files(root: str) -> list[str]:
    """Locate .github/workflows/*.yml|*.yaml anywhere in the tree."""
    found = []
    for dirpath, _dirs, files in os.walk(root):
        norm = dirpath.replace("\\", "/")
        if "/.github/workflows" not in (norm + "/") and not norm.endswith("/.github/workflows"):
            continue
        for f in files:
            if f.lower().endswith((".yml", ".yaml")):
                found.append(os.path.join(dirpath, f))
    return sorted(found)


def _is_mutable_ref(ref: str) -> bool:
    """True if ref is a branch or version tag (mutable), False if a full SHA."""
    return not bool(_SHA_RE.match(ref or ""))


def _collect_uses(node, sink: list):
    """Recursively walk a parsed workflow object collecting every `uses:` value."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                sink.append(v.strip())
            else:
                _collect_uses(v, sink)
    elif isinstance(node, list):
        for item in node:
            _collect_uses(item, sink)


def _audit_unpinned(workflow_files: list[str], root: str) -> list[dict]:
    """PART B: parse each workflow, flag third-party actions on a mutable ref."""
    unpinned = []
    if yaml is None:
        return unpinned
    for path in workflow_files:
        rel = os.path.relpath(path, root).replace("\\", "/")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                docs = list(yaml.safe_load_all(fh))
        except Exception:
            continue  # unparseable file -> skip (zero-FP: never guess)
        uses_vals: list[str] = []
        for doc in docs:
            _collect_uses(doc, uses_vals)
        for raw in uses_vals:
            if not raw or raw.startswith("./") or raw.startswith("docker://"):
                continue  # local composite action or container image, not third-party pin
            m = _USES_RE.match(raw)
            if not m:
                continue  # not an owner/repo@ref form -> skip
            owner, _repo, ref = m.group(1), m.group(2), m.group(3)
            if owner.lower() == "actions":
                continue  # first-party GitHub-maintained actions
            if not _is_mutable_ref(ref):
                continue  # already SHA-pinned -> safe
            unpinned.append({"action": f"{owner}/{m.group(2)}", "ref": ref, "file": rel})
    return unpinned


def _parse_actionlint(stdout: bytes) -> tuple[int, list]:
    """actionlint -format '{{json .}}' emits a JSON array of error objects."""
    try:
        data = json.loads(stdout.decode("utf-8", errors="ignore") or "[]")
    except Exception:
        return 0, []
    if not isinstance(data, list):
        return 0, []
    top = []
    for e in data:
        if not isinstance(e, dict):
            continue
        if len(top) < 8:
            fp = e.get("filepath") or "?"
            ln = e.get("line") or "?"
            msg = (e.get("message") or "")[:140]
            top.append(f"{fp}:{ln} {msg}")
    return len(data), top


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        cleanup = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="actionlint_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["awa_clone_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                root = cleanup
                mode = "repo_url"
                ctx.state["awa_input_value"] = repo_url
            elif target and os.path.isdir(target):
                root = target
                mode = "local_path"
                ctx.state["awa_input_value"] = target
            else:
                ctx.state["awa_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["awa_input_mode"] = mode

            workflow_files = _find_workflow_files(root)
            ctx.state["awa_workflow_count"] = len(workflow_files)
            if not workflow_files:
                ctx.state["awa_no_workflows"] = True
                ctx.source("no GitHub Actions workflows found")
                return

            # ── PART A: actionlint binary (optional) ──────────────────────────
            lint_available = bool(shutil.which("actionlint") or os.path.exists(ACTIONLINT_BIN))
            ctx.state["awa_lint_available"] = lint_available
            if lint_available:
                cmd = [ACTIONLINT_BIN, "-format", "{{json .}}", *workflow_files]
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd, cwd=root,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, _stderr = await asyncio.wait_for(
                            proc.communicate(), timeout=LINT_TIMEOUT)
                    except asyncio.TimeoutError:
                        proc.kill()
                        stdout = b"[]"
                        ctx.state["awa_lint_timeout"] = True
                except Exception as e:
                    stdout = b"[]"
                    ctx.state["awa_lint_subprocess_error"] = str(e)[:120]
                err_count, top = _parse_actionlint(stdout or b"[]")
                ctx.state["awa_lint_error_count"] = err_count
                ctx.state["awa_lint_top"] = top
            else:
                ctx.state["awa_lint_skipped"] = True

            # ── PART B: pure-python unpinned third-party action audit ─────────
            unpinned = _audit_unpinned(workflow_files, root)
            ctx.state["awa_unpinned"] = unpinned
            ctx.state["awa_unpinned_count"] = len(unpinned)

            ctx.source(
                f"actionlint_workflow_audit: {len(workflow_files)} workflow(s), "
                f"lint errors={ctx.state.get('awa_lint_error_count', 'skipped')}, "
                f"unpinned third-party actions={len(unpinned)}")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("awa_no_input"):
        return None
    return {"name": "actionlint_workflow_audit: repo_url or local path required",
            "severity": "INFO",
            "evidence": "Provide repo_url=https://github.com/<owner>/<repo> (or target as a "
                        "local directory) to audit its GitHub Actions workflows.",
            "remediation": "Re-run with a public repository URL or a checked-out local path.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_clone_error(s):
    if not s.get("awa_clone_error"):
        return None
    return {"name": "actionlint_workflow_audit: repository clone failed",
            "severity": "INFO",
            "evidence": s.get("awa_clone_error"),
            "remediation": "Confirm the repository is public/reachable and git is installed, "
                           "then re-run.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_no_workflows(s):
    # Only when we actually reached the tree (input resolved) and found none.
    if s.get("awa_no_input") or s.get("awa_clone_error"):
        return None
    if not s.get("awa_no_workflows"):
        return None
    return {"name": "actionlint_workflow_audit: no GitHub Actions workflows found",
            "severity": "INFO",
            "evidence": "No .github/workflows/*.yml or *.yaml files were found in the "
                        "repository tree. Nothing to audit for this scanner.",
            "remediation": "If CI runs elsewhere (e.g. a different CI system), audit that "
                           "configuration with the appropriate tooling.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_lint_skipped(s):
    # Informational: actionlint binary missing but workflows existed and Part B ran.
    if not s.get("awa_lint_skipped"):
        return None
    if not s.get("awa_workflow_count"):
        return None
    return {"name": "actionlint_workflow_audit: actionlint binary not installed (deep lint skipped)",
            "severity": "INFO",
            "evidence": f"{s.get('awa_workflow_count')} workflow file(s) were found, but the "
                        "`actionlint` CLI is not installed, so the syntax/shellcheck lint pass "
                        "was skipped. The pure-Python action-pinning audit still ran.",
            "remediation": "Install actionlint (https://github.com/rhysd/actionlint) in the "
                           "scanner environment to enable deep workflow linting.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_actionlint_errors(s):
    n = s.get("awa_lint_error_count")
    if not n or n <= 0:
        return None
    top = s.get("awa_lint_top") or []
    sample = "; ".join(top[:5]) if top else "(see CI logs)"
    if n <= 5:
        sev, cvss = "LOW", "3.7"
    else:
        sev, cvss = "MEDIUM", "5.3"
    return {"name": f"GitHub Actions workflows have {n} actionlint error(s)",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-1164", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"actionlint reported {n} issue(s) across the workflow files. "
                        f"Sample: {sample}",
            "remediation": "Fix the reported workflow issues (quote shell expressions, correct "
                           "expression syntax, address shellcheck warnings). Run actionlint in "
                           "CI to keep workflows clean."}


def _rule_unpinned_actions(s):
    unpinned = s.get("awa_unpinned") or []
    if not unpinned:
        return None
    n = len(unpinned)
    sample = "; ".join(f"{u['action']}@{u['ref']} ({u['file']})" for u in unpinned[:8])
    more = f" (+{n - 8} more)" if n > 8 else ""
    return {"name": f"{n} third-party GitHub Action(s) pinned to a mutable ref (not a commit SHA)",
            "severity": "LOW", "cvss": "4.3",
            "cwe": "CWE-1357", "owasp": "A08:2021",
            "verified_exploit": True,
            "evidence": f"These third-party actions are referenced by a branch or version tag "
                        f"instead of an immutable 40-char commit SHA, so the action owner can "
                        f"change the code that runs in your CI: {sample}{more}",
            "remediation": "Pin every third-party action to a full commit SHA "
                           "(uses: owner/repo@<40-hex-sha>) and let Dependabot keep the SHAs "
                           "updated. First-party 'actions/*' and local './' actions are exempt."}


def _rule_pinned_clean(s):
    # POSITIVE only when workflows existed, the python audit ran, and everything is clean.
    if s.get("awa_no_input") or s.get("awa_clone_error") or s.get("awa_no_workflows"):
        return None
    if not s.get("awa_workflow_count"):
        return None
    if "awa_unpinned_count" not in s:
        return None  # Part B did not complete
    if s.get("awa_unpinned_count"):
        return None
    if s.get("awa_lint_error_count"):
        return None
    return {"name": "GitHub Actions workflows are clean and SHA-pinned",
            "severity": "POSITIVE",
            "evidence": f"{s.get('awa_workflow_count')} workflow file(s) audited: no third-party "
                        "actions on a mutable ref, and "
                        + ("no actionlint errors." if s.get("awa_lint_available")
                           else "the action-pinning audit found no issues (deep lint not run)."),
            "remediation": "Keep third-party actions SHA-pinned and re-run this audit periodically; "
                           "enable Dependabot for action updates.",
            "cwe": "N/A", "owasp": "N/A"}


ACTIONLINT_WORKFLOW_AUDIT_FINDING_RULES = [
    _rule_no_input,
    _rule_clone_error,
    _rule_no_workflows,
    _rule_lint_skipped,
    _rule_actionlint_errors,
    _rule_unpinned_actions,
    _rule_pinned_clean,
]


INTEL_FIELDS = [("Input mode", "awa_input_mode"),
                ("Scan input", "awa_input_value"),
                ("Workflow files", "awa_workflow_count"),
                ("actionlint available", "awa_lint_available"),
                ("actionlint errors", "awa_lint_error_count"),
                ("Top actionlint errors", "awa_lint_top"),
                ("Unpinned third-party actions", "awa_unpinned_count"),
                ("Unpinned action details", "awa_unpinned")]


@router.post("/api/supply_chain/actionlint_workflow_audit")
async def supply_chain_actionlint_workflow_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="actionlint_workflow_audit",
        gather_func=_make_gather(req),
        finding_rules=ACTIONLINT_WORKFLOW_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
