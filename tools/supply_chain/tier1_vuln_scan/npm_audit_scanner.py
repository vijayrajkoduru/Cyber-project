"""npm_audit_scanner - npm audit + npm ls outdated CVE scan (playbook §2 #18).

Clones the customer's repo (or uses a local path), detects package.json,
runs `npm install --package-lock-only --no-audit` to generate a lockfile,
then `npm audit --json` to produce the official npm vulnerability report.
Categorizes by severity (info/low/moderate/high/critical) and reports the
top vulnerable packages with CVE IDs + patch versions.

Customer input via ScanRequest:
  - target           = local path to Node project root (containing package.json)
  - or repo_url      = git URL to clone for ephemeral scan
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.npm_audit_scanner_findings import NPM_AUDIT_SCANNER_FINDING_RULES

router = APIRouter()
NPM_BIN = shutil.which("npm")
GIT_BIN = shutil.which("git")
DEFAULT_TIMEOUT = 240


class NpmAuditScannerRequest(ScanRequest):
    options: Optional[dict] = None


async def _run(cmd: list[str], cwd: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return {"timeout": True, "rc": None, "stdout": b"", "stderr": b""}
        return {"timeout": False, "rc": proc.returncode,
                "stdout": stdout, "stderr": stderr}
    except FileNotFoundError as e:
        return {"error": f"binary not found: {e}", "rc": None}


async def gather(ctx: ScanContext):
    target = ctx.host
    if not NPM_BIN:
        ctx.state["npm_audit_scanner_error"] = "npm binary not installed"
        ctx.source("npm missing")
        return

    repo_url = getattr(ctx.state.get("_request_ref", {}), "repo_url", None) or None
    # Look in _options first (where the orchestrator stashes optional fields)
    opts = ctx.state.get("_options") or {}
    repo_url = repo_url or opts.get("repo_url")

    scan_dir = None
    cleanup_dir = None
    try:
        if target and Path(target).is_dir() and Path(target, "package.json").is_file():
            scan_dir = target
        elif repo_url and GIT_BIN:
            cleanup_dir = tempfile.mkdtemp(prefix="vlnpm_")
            clone_res = await _run([GIT_BIN, "clone", "--depth", "1", repo_url, cleanup_dir],
                                  timeout=120)
            if clone_res.get("rc") != 0:
                ctx.state["npm_audit_scanner_error"] = "git clone failed"
                ctx.source(f"clone failed: {repo_url[:60]}")
                return
            scan_dir = cleanup_dir
        else:
            ctx.state["npm_audit_scanner_error"] = "target path with package.json OR repo_url required"
            ctx.source("no scannable target")
            return

        if not Path(scan_dir, "package.json").is_file():
            ctx.state["npm_audit_scanner_error"] = "no package.json found in scan dir"
            ctx.source("no package.json")
            return

        # Ensure lockfile exists (npm audit requires it)
        if not Path(scan_dir, "package-lock.json").is_file():
            await _run([NPM_BIN, "install", "--package-lock-only",
                       "--no-audit", "--no-fund", "--ignore-scripts"],
                      cwd=scan_dir, timeout=180)

        # Run audit
        audit_res = await _run([NPM_BIN, "audit", "--json", "--audit-level=info"],
                              cwd=scan_dir, timeout=120)
        # npm audit returns non-zero when vulns found — that's normal
        if audit_res.get("timeout"):
            ctx.state["npm_audit_scanner_error"] = "npm audit timeout"
            ctx.source("npm audit timeout")
            return

        try:
            data = json.loads((audit_res.get("stdout", b"") or b"").decode("utf-8", errors="ignore"))
        except json.JSONDecodeError as e:
            ctx.state["npm_audit_scanner_error"] = f"audit JSON parse: {str(e)[:80]}"
            ctx.source("json parse failed")
            return

        metadata = data.get("metadata", {})
        vuln_summary = metadata.get("vulnerabilities", {})
        # npm v7+ structure
        total_deps = metadata.get("totalDependencies", 0) or sum(metadata.get("dependencies", {}).values())

        vulns = data.get("vulnerabilities", {})
        top_vulns = []
        for pkg_name, info in list(vulns.items())[:20]:
            severity = info.get("severity", "?")
            via = info.get("via") or []
            cves = []
            for v in via:
                if isinstance(v, dict):
                    url = v.get("url", "")
                    if "CVE-" in str(v.get("title", "")) or "CVE-" in url:
                        # extract CVE-XXXX-NNNN from title or url
                        import re as _re
                        cve_match = _re.search(r"CVE-\d{4}-\d+", str(v.get("title", "")) + " " + url)
                        if cve_match:
                            cves.append(cve_match.group(0))
            fixAvailable = info.get("fixAvailable")
            top_vulns.append({
                "package": pkg_name,
                "severity": severity,
                "cves": cves[:3],
                "fix_available": bool(fixAvailable) if fixAvailable is not None else None,
                "range": info.get("range", "?"),
            })

        ctx.state["npm_total_dependencies"] = total_deps
        ctx.state["npm_vuln_summary"] = vuln_summary
        ctx.state["npm_top_vulnerabilities"] = top_vulns
        ctx.state["npm_audit_scanner_total"] = (
            (vuln_summary.get("critical", 0) or 0) +
            (vuln_summary.get("high", 0) or 0)
        )
        ctx.source(f"npm audit: total deps={total_deps}; "
                   f"critical={vuln_summary.get('critical', 0)}, "
                   f"high={vuln_summary.get('high', 0)}, "
                   f"moderate={vuln_summary.get('moderate', 0)}")
    finally:
        if cleanup_dir:
            try: shutil.rmtree(cleanup_dir, ignore_errors=True)
            except Exception: pass


INTEL_FIELDS = [("Total dependencies", "npm_total_dependencies"),
                ("Severity histogram", "npm_vuln_summary"),
                ("Top vulnerabilities", "npm_top_vulnerabilities")]


@router.post("/api/supply_chain/npm_audit_scanner")
async def supply_chain_npm_audit_scanner(req: NpmAuditScannerRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}
    options = {**options, "repo_url": req.repo_url}  # surface ScanRequest.repo_url into _options
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="npm_audit_scanner",
        gather_func=_gather_with_options, finding_rules=NPM_AUDIT_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
