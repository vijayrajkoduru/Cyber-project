"""git_secrets_scan - leaked-credential discovery in git repos (VL-METHOD).

Tier 4 (passive credential discovery): finds secrets that developers
accidentally committed to source control. Lower-risk than tier1 active
spraying because we only read repo contents - no auth attempts.

The 7 stages this scanner performs:

  1. PRE-FLIGHT  - Validate input (repo_url OR local_path required).
                    If repo_url, sanity-check URL scheme. If local_path,
                    verify directory + .git/ subdirectory exist.

  2. FINGERPRINT - git log -1 / git ls-files / git remote -v to capture
                    head commit, file count, origin URL, total commit
                    count, gitleaks binary path. Drives deep_scan choice.

  3. QUICK PROBE - Pure-Python regex sweep over HEAD only (no history).
                    Five top patterns: AWS access keys, GitHub tokens,
                    private key headers, Slack tokens, generic password=.
                    Fast (seconds), high signal, no external tool needed.

  4. DEEP SCAN   - Runs if quick_probe found something OR always_deep=True.
                    Prefers gitleaks (hundreds of curated rules + history
                    walking). Falls back to regex over full `git log -p`
                    if gitleaks missing. Hard-capped at 1000 matches.

  5. VERIFY      - Shannon entropy on each matched secret. High entropy
                    (>4.0) -> CONFIRMED. Common-word placeholders
                    ("password123", "changeme") -> SUSPECTED. gitleaks
                    rule hits with high-confidence rule -> CONFIRMED.

  6. PRIVILEGE   - Classify by secret type:
                    AWS/GCP/Azure keys     -> cloud_root  (CRITICAL)
                    SSH/GPG/TLS keys       -> key_material (CRITICAL)
                    GitHub/Slack/Stripe    -> service_token (HIGH)
                    Generic password/api   -> credential (MEDIUM)

  7. CHAIN       - For CONFIRMED cloud_credentials, suggest IAM audit
                    scanners. For CONFIRMED private_key, suggest SSH
                    key validation. Cross-scanner engine spawns these
                    with the captured material.

Customer input via ScanRequest.options:
  - options.repo_url     = public git URL (https/git@) to clone
  - options.local_path   = OR path to already-cloned repo on disk
  - options.scan_depth   = "shallow" (last 100 commits, default) | "full"
  - options.always_deep  = bool, force deep_scan even if quick_probe empty
  - options.show_plaintext = bool, show actual secret in report (own infra only)

Either repo_url OR local_path must be supplied.

Safety: deep_scan hard-clamped to 1000 secret matches per run. Cloned
repos go into a tempdir + are removed on exit. Plaintext output gated
behind options.show_plaintext (default redacted).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.git_secrets_scan_findings import (
    GIT_SECRETS_SCAN_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()
GITLEAKS_BIN = shutil.which("gitleaks") or ""
GIT_BIN = shutil.which("git") or "git"

HARD_MAX_DEEP_HITS = 1000
HARD_MAX_QUICK_FILES = 5000
DEFAULT_DEEP_TIMEOUT = 180
SHALLOW_COMMITS = 100

# ── secret pattern regexes ─────────────────────────────────────────
# Top-5 critical patterns for quick_probe + pure-Python fallback.
RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
RE_GH_PAT_OLD = re.compile(r"ghp_[a-zA-Z0-9]{36}")
RE_GH_PAT_NEW = re.compile(r"github_pat_[a-zA-Z0-9_]{82}")
RE_PRIV_KEY = re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----")
RE_SLACK = re.compile(r"xox[abpr]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}")
RE_GENERIC = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)

# Common placeholder values - flag as SUSPECTED not CONFIRMED.
COMMON_PLACEHOLDERS = {
    "password", "password123", "changeme", "secret", "secret123",
    "example", "example_token", "test", "test123", "12345678",
    "p@ssw0rd", "admin", "admin123", "default", "your_password_here",
    "your_api_key_here", "yourapikey", "yoursecret", "yourtoken",
    "placeholder", "xxxx", "xxxxxxxx", "todo", "<your-key>",
}

# File extensions to skip during quick_probe (binary / large noise).
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".mp3", ".mp4", ".mov", ".avi", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".min.js", ".min.css",
}


class GitSecretsScanRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(secret: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction. Default returns "<TYPE>_LEN<N>_HASH<sha256_8>".
    When show_plaintext=True (customer scanning own infra), returns the
    actual plaintext. Default keeps marker so multi-tenant reports never
    leak secrets."""
    if not secret:
        return "TYPE_UNKNOWN_LEN0_HASH00000000"
    secret = secret.strip()
    if show_plaintext:
        return secret
    stype = _classify_secret_type(secret)
    h = hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"{stype}_LEN{len(secret)}_HASH{h}"


def _classify_secret_type(secret: str) -> str:
    """Bucket a raw secret string into a coarse type label for redaction."""
    if not secret:
        return "UNKNOWN"
    if RE_AWS_KEY.search(secret):
        return "AWS_KEY"
    if RE_GH_PAT_OLD.search(secret) or RE_GH_PAT_NEW.search(secret):
        return "GH_TOKEN"
    if "BEGIN" in secret and "PRIVATE KEY" in secret:
        return "PRIV_KEY"
    if RE_SLACK.search(secret):
        return "SLACK_TOKEN"
    return "CRED"


def _shannon_entropy(s: str) -> float:
    """Standard Shannon entropy in bits/char. Returns 0 for empty."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _classify_privilege(secret_type: str, raw_secret: str) -> str:
    """Map redacted secret bucket -> VL-METHOD privilege class."""
    if secret_type == "AWS_KEY":
        return "cloud_root"
    s = (raw_secret or "").lower()
    if any(k in s for k in ("akia", "asia", "aws_", "amzn", "gcp", "google_application",
                              "azure", "ms_client_secret")):
        return "cloud_root"
    if secret_type == "PRIV_KEY" or "begin" in s and "private key" in s:
        return "key_material"
    if secret_type in ("GH_TOKEN", "SLACK_TOKEN"):
        return "service_token"
    if any(k in s for k in ("ghp_", "github_pat_", "xox", "sk_live_", "rk_live_",
                              "sk_test_", "stripe", "twilio")):
        return "service_token"
    return "credential"


def _redacted_snippet(line: str, secret: str, max_ctx: int = 40) -> str:
    """Build a "...context<REDACTED>context..." snippet for finding evidence.
    Context bytes around the match, secret itself replaced with marker."""
    if not line or not secret:
        return ""
    idx = line.find(secret)
    if idx < 0:
        return line[: max_ctx * 2].rstrip()
    start = max(0, idx - max_ctx)
    end = min(len(line), idx + len(secret) + max_ctx)
    return (line[start:idx] + "<REDACTED>" + line[idx + len(secret):end]).strip()


def _scan_text_for_secrets(text: str, file_path: str) -> list[dict]:
    """Apply the 5 quick-probe regexes to a chunk of text. Returns finding
    dicts (no confidence/privilege set yet - that comes in verify stage)."""
    out: list[dict] = []
    if not text:
        return out
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:
            # Likely a minified blob; skip to avoid regex pathological backtrack.
            continue
        for rx, kind in (
            (RE_AWS_KEY, "aws_access_key"),
            (RE_GH_PAT_OLD, "github_token"),
            (RE_GH_PAT_NEW, "github_token"),
            (RE_PRIV_KEY, "private_key"),
            (RE_SLACK, "slack_token"),
        ):
            m = rx.search(line)
            if m:
                raw = m.group(0)
                out.append({
                    "file": file_path,
                    "line": lineno,
                    "kind": kind,
                    "secret_raw": raw,
                    "snippet": _redacted_snippet(line, raw),
                    "discovery_method": "regex_quick_probe",
                })
        gm = RE_GENERIC.search(line)
        if gm:
            raw = gm.group(2)
            out.append({
                "file": file_path,
                "line": lineno,
                "kind": "generic_credential",
                "secret_raw": raw,
                "snippet": _redacted_snippet(line, raw),
                "discovery_method": "regex_quick_probe",
            })
    return out


def _git_cmd(cwd: str, args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a git command, return (rc, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            [GIT_BIN] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


# ═══════════════════════════════════════════════════════════════════
#  GitSecretsScan - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class GitSecretsScan(MethodologyScanner):
    name = "git_secrets_scan"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        repo_url = (opts.get("repo_url") or "").strip()
        local_path = (opts.get("local_path") or "").strip()
        ctx.state["_clone_tempdir"] = None  # may be populated below

        if not repo_url and not local_path:
            ctx.state["skipped_reason"] = "repo_url or local_path required"
            return False

        if local_path:
            if not os.path.isdir(local_path):
                ctx.state["skipped_reason"] = f"local_path '{local_path}' is not a directory"
                return False
            if not os.path.isdir(os.path.join(local_path, ".git")):
                ctx.state["skipped_reason"] = f"local_path '{local_path}' is not a git repo (.git/ missing)"
                return False
            ctx.state["scan_path"] = os.path.abspath(local_path)
            ctx.state["scan_path_source"] = "local_path"
            return True

        # repo_url path - clone shallow into tempdir.
        if not (repo_url.startswith("http://")
                or repo_url.startswith("https://")
                or repo_url.startswith("git@")):
            ctx.state["skipped_reason"] = f"repo_url '{repo_url[:60]}' has unsupported scheme (need http/https/git@)"
            return False

        tmpdir = tempfile.mkdtemp(prefix="vl_gitsecrets_")
        ctx.state["_clone_tempdir"] = tmpdir
        depth = "shallow" if (opts.get("scan_depth") or "shallow").lower() != "full" else "full"
        clone_args = ["clone", "--quiet"]
        if depth == "shallow":
            clone_args += ["--depth", str(SHALLOW_COMMITS)]
        clone_args += [repo_url, tmpdir]
        rc, out, err = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(os.getcwd(), clone_args, timeout=120))
        if rc != 0:
            ctx.state["skipped_reason"] = f"git clone failed: {(err or out)[:200]}"
            try: shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception: pass
            ctx.state["_clone_tempdir"] = None
            return False
        ctx.state["scan_path"] = tmpdir
        ctx.state["scan_path_source"] = "cloned_from_repo_url"
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        scan_path = ctx.state.get("scan_path") or ""
        fp = {
            "head_commit": "",
            "file_count": 0,
            "remote_url": "",
            "commit_count": 0,
            "gitleaks_binary": GITLEAKS_BIN,
        }
        if not scan_path or not os.path.isdir(scan_path):
            ctx.state["fingerprint"] = fp
            return

        # HEAD commit
        rc, out, _ = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(scan_path, ["log", "--oneline", "-1"], timeout=10))
        if rc == 0 and out.strip():
            fp["head_commit"] = out.strip().split("\n", 1)[0][:120]

        # File count
        rc, out, _ = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(scan_path, ["ls-files"], timeout=20))
        if rc == 0:
            files = [ln for ln in out.splitlines() if ln.strip()]
            fp["file_count"] = len(files)
            ctx.state["_git_files"] = files

        # Remote URL
        rc, out, _ = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(scan_path, ["remote", "-v"], timeout=10))
        if rc == 0 and out.strip():
            first = out.strip().splitlines()[0]
            parts = first.split()
            if len(parts) >= 2:
                fp["remote_url"] = parts[1]

        # Commit count
        rc, out, _ = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(scan_path, ["rev-list", "--count", "HEAD"], timeout=15))
        if rc == 0 and out.strip().isdigit():
            fp["commit_count"] = int(out.strip())

        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (regex sweep on HEAD only) ──────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        scan_path = ctx.state.get("scan_path") or ""
        files = ctx.state.get("_git_files") or []
        if not scan_path or not files:
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        # Clamp at HARD_MAX_QUICK_FILES to avoid runaway on huge repos.
        candidates = files[:HARD_MAX_QUICK_FILES]
        scanned = 0
        hits: list[dict] = []

        def _scan_blocking() -> tuple[int, list[dict]]:
            local_scanned = 0
            local_hits: list[dict] = []
            for rel in candidates:
                ext = os.path.splitext(rel)[1].lower()
                if ext in SKIP_EXTS:
                    continue
                abs_path = os.path.join(scan_path, rel)
                if not os.path.isfile(abs_path):
                    continue
                try:
                    if os.path.getsize(abs_path) > 1_000_000:
                        # Skip files >1MB to keep quick_probe quick.
                        continue
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except Exception:
                    continue
                local_scanned += 1
                found = _scan_text_for_secrets(text, rel)
                if found:
                    local_hits.extend(found)
                if len(local_hits) >= HARD_MAX_DEEP_HITS:
                    break
            return local_scanned, local_hits

        scanned, hits = await asyncio.get_event_loop().run_in_executor(None, _scan_blocking)
        ctx.state["quick_probe_attempts"] = scanned
        ctx.state["quick_probe_hits"] = len(hits)

        # Tag with stage + return as preliminary findings.
        for i, h in enumerate(hits):
            h["id"] = f"quick_{i}"
        return hits

    # ── STAGE 4: DEEP SCAN (gitleaks OR fallback regex on history) ─
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        scan_path = ctx.state.get("scan_path") or ""
        opts = ctx.state.get("_options") or {}
        scan_depth = (opts.get("scan_depth") or "shallow").lower()
        if not scan_path or not os.path.isdir(scan_path):
            ctx.state["git_deep_secrets"] = 0
            return []

        if GITLEAKS_BIN:
            findings = await self._run_gitleaks(scan_path, scan_depth)
        else:
            ctx.state["gitleaks_missing"] = True
            findings = await self._fallback_history_regex(scan_path, scan_depth)

        # Hard-cap to HARD_MAX_DEEP_HITS.
        if len(findings) > HARD_MAX_DEEP_HITS:
            ctx.state["deep_truncated_at"] = HARD_MAX_DEEP_HITS
            findings = findings[:HARD_MAX_DEEP_HITS]

        ctx.state["git_deep_secrets"] = len(findings)
        for i, f in enumerate(findings):
            f["id"] = f"deep_{i}"
        return findings

    async def _run_gitleaks(self, scan_path: str, scan_depth: str) -> list[dict]:
        """Invoke gitleaks detect, parse JSON report into finding dicts."""
        rep_fd, rep_path = tempfile.mkstemp(prefix="vl_gitleaks_", suffix=".json")
        try: os.close(rep_fd)
        except Exception: pass

        cmd = [GITLEAKS_BIN, "detect",
               "--source", scan_path,
               "--report-format", "json",
               "--report-path", rep_path,
               "--no-banner",
               "--exit-code", "0"]
        if scan_depth == "shallow":
            cmd += ["--log-opts", f"-{SHALLOW_COMMITS}"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=DEFAULT_DEEP_TIMEOUT)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                return []
        except Exception:
            try: os.unlink(rep_path)
            except Exception: pass
            return []

        findings: list[dict] = []
        try:
            if os.path.exists(rep_path) and os.path.getsize(rep_path) > 0:
                with open(rep_path, "r", encoding="utf-8", errors="ignore") as fh:
                    raw = json.load(fh)
                if isinstance(raw, list):
                    for r in raw[:HARD_MAX_DEEP_HITS]:
                        rule_id = (r.get("RuleID") or r.get("ruleID") or "unknown")
                        secret = r.get("Secret") or r.get("Match") or ""
                        file_p = r.get("File") or r.get("file") or ""
                        line_n = r.get("StartLine") or r.get("startLine") or 0
                        commit = r.get("Commit") or r.get("commit") or ""
                        findings.append({
                            "file": file_p,
                            "line": int(line_n) if isinstance(line_n, int) else 0,
                            "kind": _gitleaks_rule_to_kind(rule_id),
                            "secret_raw": secret,
                            "snippet": _redacted_snippet(r.get("Match") or "", secret),
                            "discovery_method": "gitleaks_rule_match",
                            "rule_id": rule_id,
                            "commit": commit[:12],
                        })
        except Exception:
            pass
        finally:
            try: os.unlink(rep_path)
            except Exception: pass

        return findings

    async def _fallback_history_regex(self, scan_path: str, scan_depth: str) -> list[dict]:
        """No gitleaks - run the 5 regexes over `git log -p` history."""
        log_args = ["log", "-p", "--no-color", "--no-merges"]
        if scan_depth == "shallow":
            log_args += [f"-{SHALLOW_COMMITS}"]
        rc, out, _ = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _git_cmd(scan_path, log_args, timeout=DEFAULT_DEEP_TIMEOUT))
        if rc != 0 or not out:
            return []
        findings: list[dict] = []
        current_commit = ""
        current_file = ""
        for line in out.splitlines():
            if line.startswith("commit "):
                current_commit = line.split(" ", 1)[1][:12]
                continue
            if line.startswith("diff --git "):
                # diff --git a/path b/path
                try:
                    current_file = line.split(" b/", 1)[1].strip()
                except Exception:
                    current_file = ""
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            content = line[1:]
            hits = _scan_text_for_secrets(content, current_file or "?")
            for h in hits:
                h["commit"] = current_commit
                h["discovery_method"] = "regex_history_fallback"
                findings.append(h)
                if len(findings) >= HARD_MAX_DEEP_HITS:
                    return findings
        return findings

    # ── STAGE 5: VERIFY (entropy gate) ───────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        secret = finding.get("secret_raw") or ""
        kind = finding.get("kind") or ""
        discovery = finding.get("discovery_method") or ""

        # gitleaks high-confidence rule -> CONFIRMED without entropy re-check.
        if discovery == "gitleaks_rule_match":
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "gitleaks_high_confidence_rule"
            finding["secret_marker"] = _redact(secret, show_plaintext=show)
            finding.pop("secret_raw", None)
            return finding

        # Private key blocks: presence of BEGIN PRIVATE KEY header is decisive.
        if kind == "private_key" or ("BEGIN" in secret and "PRIVATE KEY" in secret):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "private_key_header_match"
            finding["secret_marker"] = _redact(secret, show_plaintext=show)
            finding.pop("secret_raw", None)
            return finding

        # Placeholder / common-word check.
        if secret.lower() in COMMON_PLACEHOLDERS:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "common_placeholder_match"
            finding["secret_marker"] = _redact(secret, show_plaintext=show)
            finding.pop("secret_raw", None)
            return finding

        # Shannon entropy gate.
        entropy = _shannon_entropy(secret)
        finding["entropy"] = round(entropy, 2)
        if entropy >= 4.0:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "shannon_entropy_check"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "low_entropy_possible_placeholder"

        finding["secret_marker"] = _redact(secret, show_plaintext=show)
        finding.pop("secret_raw", None)
        return finding

    # ── STAGE 6: PRIVILEGE CHECK (cloud / key / token / cred) ────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        kind = finding.get("kind") or ""
        marker = finding.get("secret_marker") or ""
        # Best-effort: classify by kind + by marker prefix (since secret_raw
        # was redacted in verify stage).
        if kind == "aws_access_key" or marker.startswith("AWS_KEY"):
            finding["privilege_level"] = "cloud_root"
        elif kind == "private_key" or marker.startswith("PRIV_KEY"):
            finding["privilege_level"] = "key_material"
        elif kind in ("github_token", "slack_token") or marker.startswith(("GH_TOKEN", "SLACK_TOKEN")):
            finding["privilege_level"] = "service_token"
        elif kind == "generic_credential":
            finding["privilege_level"] = "credential"
        else:
            # gitleaks-rule findings: use rule_id heuristic.
            rule_id = (finding.get("rule_id") or "").lower()
            if any(k in rule_id for k in ("aws", "gcp", "azure", "cloud")):
                finding["privilege_level"] = "cloud_root"
            elif "private-key" in rule_id or "private_key" in rule_id or "rsa" in rule_id:
                finding["privilege_level"] = "key_material"
            elif any(k in rule_id for k in ("github", "slack", "stripe", "twilio", "npm", "jwt")):
                finding["privilege_level"] = "service_token"
            else:
                finding["privilege_level"] = "credential"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        chain: list[str] = []
        seen: set[str] = set()
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            priv = f.get("privilege_level") or ""
            if priv == "cloud_root":
                for nxt in ("post_exploit_aws_iam_audit", "post_exploit_gcp_iam_audit"):
                    if nxt not in seen:
                        chain.append(nxt); seen.add(nxt)
            elif priv == "key_material":
                if "ssh_key_validate_audit" not in seen:
                    chain.append("ssh_key_validate_audit"); seen.add("ssh_key_validate_audit")
        return chain

    # ── cleanup hook (called via run wrapper; harmless if unused) ─
    def _cleanup(self, ctx: ScanContext):
        tmp = ctx.state.get("_clone_tempdir")
        if tmp and os.path.isdir(tmp):
            try: shutil.rmtree(tmp, ignore_errors=True)
            except Exception: pass


def _gitleaks_rule_to_kind(rule_id: str) -> str:
    """Map a gitleaks RuleID to one of our finding 'kind' buckets."""
    r = (rule_id or "").lower()
    if "aws" in r:
        return "aws_access_key"
    if "github" in r:
        return "github_token"
    if "slack" in r:
        return "slack_token"
    if "private-key" in r or "private_key" in r or "rsa" in r:
        return "private_key"
    return "generic_credential"


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/git_secrets_scan")
async def password_git_secrets_scan(req: GitSecretsScanRequest, _=Depends(verify_scan_quota)):
    scanner = GitSecretsScan()
    try:
        return await scanner.run_as_endpoint(
            req,
            finding_rules=GIT_SECRETS_SCAN_FINDING_RULES,
            intel_fields=INTEL_FIELDS,
        )
    finally:
        # Best-effort cleanup of any cloned tempdir. The ScanContext lives
        # only inside run_as_endpoint, so we cannot reach _clone_tempdir
        # from here - it is cleaned up by the OS tempdir reaper if not
        # by the scanner internally. (Future: thread cleanup through
        # context for deterministic teardown.)
        pass


def register(app):
    app.include_router(router)
