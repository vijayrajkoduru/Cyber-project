"""gitleaks_secrets_scan - Repo secret-leak audit via gitleaks (playbook §4 #52).

Shallow-clones the customer's repo (ScanRequest.repo_url), runs gitleaks
against the working tree, and parses the JSON report. Findings are
re-emitted WITHOUT the leaked secret value - only the file path, line
number, and Gitleaks rule ID are exposed (masking is mandatory per the
zero-FP policy: leaked-secret reports become PII themselves if reproduced).

If repo_url is missing, returns INFO with the required input. If the repo
clone fails (private repo, network), returns INFO with the error - this is
not a finding about the customer's posture.

Customer input: ScanRequest.repo_url (https://... or git@...).
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.gitleaks_secrets_scan_findings import GITLEAKS_SECRETS_SCAN_FINDING_RULES

router = APIRouter()
GITLEAKS_BIN = shutil.which("gitleaks") or "/usr/local/bin/gitleaks"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 180


async def _shallow_clone(repo_url: str, dest: str) -> tuple[bool, str]:
    if not shutil.which("git") and not os.path.exists(GIT_BIN):
        return False, "git not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            GIT_BIN, "clone", "--depth", "1", "--no-tags", "--quiet", repo_url, dest,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
        except asyncio.TimeoutError:
            proc.kill()
            return False, "git clone timeout"
    except Exception as e:
        return False, f"git clone error: {str(e)[:80]}"
    if proc.returncode != 0:
        return False, f"git clone rc={proc.returncode}: {stderr.decode('utf-8', errors='ignore')[:160]}"
    return True, ""


def _mask_secret(s: str) -> str:
    """Mask a leaked secret value - keep first 4 + last 2 chars only."""
    if not s:
        return ""
    s = str(s)
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}{'*' * (len(s) - 6)}{s[-2:]}"


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        if not repo_url:
            ctx.state["gitleaks_secrets_scan_no_input"] = True
            ctx.source("repo_url required")
            return
        if not shutil.which("gitleaks") and not os.path.exists(GITLEAKS_BIN):
            ctx.state["gitleaks_secrets_scan_error"] = "gitleaks binary not installed"
            ctx.source("gitleaks missing")
            return

        ctx.state["gitleaks_repo_url"] = repo_url
        tmp_clone = tempfile.mkdtemp(prefix="gitleaks_repo_")
        report_path = os.path.join(tmp_clone, "_gitleaks_report.json")
        try:
            ok, err = await _shallow_clone(repo_url, os.path.join(tmp_clone, "repo"))
            if not ok:
                ctx.state["gitleaks_secrets_scan_error"] = err
                ctx.source(f"clone failed: {err}")
                return

            # gitleaks v8+: `gitleaks dir <path>` (working-tree scan).
            # Use --no-banner + --redact for safe output; we still re-mask below.
            cmd = [GITLEAKS_BIN, "dir", os.path.join(tmp_clone, "repo"),
                   "--report-format", "json", "--report-path", report_path,
                   "--no-banner", "--redact", "--exit-code", "0"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["gitleaks_secrets_scan_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["gitleaks_secrets_scan_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source(f"subprocess failed: {str(e)[:80]}")
                return

            # gitleaks writes an empty file (or nothing) if there are no leaks.
            if not os.path.exists(report_path):
                # Fallback for older CLI: try `detect` subcommand.
                fallback_cmd = [GITLEAKS_BIN, "detect", "--source", os.path.join(tmp_clone, "repo"),
                                "--report-format", "json", "--report-path", report_path,
                                "--no-banner", "--redact", "--exit-code", "0", "--no-git"]
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *fallback_cmd,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except Exception:
                    pass

            findings_safe: list[dict] = []
            by_rule: dict[str, int] = {}
            by_file: dict[str, int] = {}
            if os.path.exists(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read().strip()
                    if content:
                        report = json.loads(content)
                        if isinstance(report, dict):
                            report = [report]
                        for leak in (report or []):
                            if not isinstance(leak, dict):
                                continue
                            rule_id = leak.get("RuleID") or leak.get("Rule") or "?"
                            description = leak.get("Description") or ""
                            file_path = leak.get("File") or "?"
                            start_line = leak.get("StartLine") or 0
                            secret = leak.get("Secret") or ""
                            findings_safe.append({
                                "rule": rule_id,
                                "description": description[:120],
                                "file": file_path,
                                "line": int(start_line) if isinstance(start_line, (int, float)) else 0,
                                "masked_secret": _mask_secret(secret),
                            })
                            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
                            by_file[file_path] = by_file.get(file_path, 0) + 1
                except Exception as e:
                    ctx.state["gitleaks_secrets_scan_error"] = f"report parse: {str(e)[:120]}"
                    ctx.source("bad json report")
                    return

            ctx.state["gitleaks_total_leaks"] = len(findings_safe)
            ctx.state["gitleaks_by_rule"] = by_rule
            ctx.state["gitleaks_by_file"] = dict(sorted(by_file.items(), key=lambda x: -x[1])[:10])
            ctx.state["gitleaks_findings"] = findings_safe[:25]
            ctx.source(f"gitleaks: {len(findings_safe)} leak(s) "
                       f"across {len(by_file)} file(s)")
        finally:
            try:
                shutil.rmtree(tmp_clone, ignore_errors=True)
            except Exception:
                pass
    return gather


INTEL_FIELDS = [("Repo scanned", "gitleaks_repo_url"),
                ("Total leaks", "gitleaks_total_leaks"),
                ("Leaks by rule", "gitleaks_by_rule"),
                ("Top affected files", "gitleaks_by_file"),
                ("Findings (masked)", "gitleaks_findings")]


@router.post("/api/supply_chain/gitleaks_secrets_scan")
async def supply_chain_gitleaks_secrets_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="gitleaks_secrets_scan",
        gather_func=_make_gather(req),
        finding_rules=GITLEAKS_SECRETS_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
