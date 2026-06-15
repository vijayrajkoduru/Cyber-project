"""Checkov IaC policy scan — real engine (Vuln tier9 §9, deep).

Complements the regex-only iac_misconfig_scan with Bridgecrew Checkov, a
full multi-framework policy engine (Terraform, CloudFormation, Kubernetes,
Dockerfile, ARM, Serverless, Helm). Hundreds of CKV_* policies vs the ~18
inline regex rules.

Customer input precedence:
  1. ScanRequest.iac_text  -> written to a temp dir, scanned
  2. ScanRequest.repo_url  -> shallow clone, scanned recursively
  3. ScanRequest.target    -> if it's an existing local dir

Zero false positives: every finding is a Checkov FAILED policy with its CKV id,
file, line range, resource, and guideline. NOT-APPLICABLE skip when no input.
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import tempfile
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()
CHECKOV_BIN = shutil.which("checkov") or "/usr/local/bin/checkov"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240


class CheckovScanRequest(ScanRequest):
    iac_text: Optional[str] = None
    iac_filename: Optional[str] = None
    repo_url: Optional[str] = None


async def _shallow_clone(repo_url: str, dest: str) -> tuple[bool, str]:
    if not (shutil.which("git") or os.path.exists(GIT_BIN)):
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


def _norm_results(data):
    """Checkov emits either a single {check_type,results} object or a LIST of
    them (one per detected framework). Return the merged failed_checks list."""
    blocks = data if isinstance(data, list) else [data]
    failed = []
    summary = {"passed": 0, "failed": 0}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        res = b.get("results") or {}
        for fc in (res.get("failed_checks") or []):
            fc["_framework"] = b.get("check_type") or "?"
            failed.append(fc)
        s = b.get("summary") or {}
        summary["passed"] += s.get("passed", 0) or 0
        summary["failed"] += s.get("failed", 0) or 0
    return failed, summary


def _sev_of(fc):
    s = (fc.get("severity") or "").upper()
    return s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"


async def gather(ctx, *, iac_text="", filename="", repo_url="", target=""):
    if not (shutil.which("checkov") or os.path.exists(CHECKOV_BIN)):
        ctx.state["checkov_error"] = "checkov binary not installed"
        ctx.source("checkov missing")
        return

    cleanup = ""
    scan_dir = ""
    try:
        if (iac_text or "").strip():
            cleanup = tempfile.mkdtemp(prefix="ckv_iac_")
            fn = filename or "main.tf"
            # keep only the basename so a malicious filename can't escape the dir
            with open(os.path.join(cleanup, os.path.basename(fn)), "w", encoding="utf-8") as fh:
                fh.write(iac_text)
            scan_dir = cleanup
            ctx.state["checkov_input"] = f"pasted {len(iac_text)} bytes ({fn})"
        elif (repo_url or "").strip():
            cleanup = tempfile.mkdtemp(prefix="ckv_repo_")
            ok, err = await _shallow_clone(repo_url, cleanup)
            if not ok:
                ctx.state["checkov_error"] = err
                ctx.source(f"clone failed: {err}")
                return
            scan_dir = cleanup
            ctx.state["checkov_input"] = repo_url
        elif target and os.path.isdir(target):
            scan_dir = target
            ctx.state["checkov_input"] = target
        else:
            ctx.state["skipped_reason"] = (
                "No IaC provided. Paste Terraform/CloudFormation/K8s into iac_text, "
                "or pass repo_url, to run Checkov."
            )
            return

        ctx.source("checkov")
        cmd = [CHECKOV_BIN, "-d", scan_dir, "-o", "json", "--compact", "--quiet"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                ctx.state["checkov_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except Exception as e:
            ctx.state["checkov_error"] = f"subprocess: {str(e)[:120]}"
            ctx.source("subprocess failed")
            return

        # checkov returns rc=1 when policies fail — that's normal, not an error.
        if not stdout:
            err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            ctx.state["checkov_error"] = f"checkov rc={proc.returncode}: {err}"
            ctx.source(f"checkov rc={proc.returncode}")
            return
        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            ctx.state["checkov_error"] = f"json parse: {str(e)[:120]}"
            ctx.source("bad json")
            return

        failed, summary = _norm_results(data)
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        items = []
        for fc in failed:
            sev = _sev_of(fc)
            by_sev[sev] += 1
            lr = fc.get("file_line_range") or []
            items.append({
                "id": fc.get("check_id") or "CKV",
                "name": (fc.get("check_name") or "")[:140],
                "severity": sev,
                "framework": fc.get("_framework"),
                "resource": (fc.get("resource") or "")[:120],
                "file": (fc.get("file_path") or "")[:120],
                "lines": lr[:2],
                "guideline": fc.get("guideline") or "",
            })
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        items.sort(key=lambda x: (order.get(x["severity"], 9), x["id"]))
        ctx.state["checkov_items"] = items
        ctx.state["checkov_failed"] = len(items)
        ctx.state["checkov_passed"] = summary.get("passed", 0)
        ctx.state["checkov_sev"] = by_sev
        ctx.source(f"checkov: {len(items)} failed policy(ies), {summary.get('passed',0)} passed")
    finally:
        if cleanup:
            try:
                shutil.rmtree(cleanup, ignore_errors=True)
            except Exception:
                pass


def _mk(i):
    def rule(s):
        items = s.get("checkov_items") or []
        if i >= len(items):
            return None
        it = items[i]
        loc = f"{it['file']}" + (f" L{it['lines'][0]}" if it.get("lines") else "")
        return {"name": f"{it['id']}: {it['name']}",
                "severity": it["severity"], "cwe": "CWE-1008",
                "evidence": f"Checkov [{it['framework']}] failed on resource '{it['resource']}' "
                            f"in {loc}.",
                "remediation": (f"Fix per the Checkov policy. Guideline: {it['guideline']}"
                                if it.get("guideline")
                                else "Remediate the failed policy; see Checkov docs for the check id.")}
    return rule


def _r_binary(s):
    err = s.get("checkov_error") or ""
    if "checkov binary not installed" not in err:
        return None
    return {"name": "checkov not installed", "severity": "INFO", "evidence": err,
            "remediation": "Install checkov (pip install checkov) in the scanner image.", "cwe": "N/A"}


def _r_clean(s):
    if s.get("checkov_items") is None or s.get("checkov_error"):
        return None
    if s.get("checkov_items"):
        return None
    return {"name": "Checkov clean (no failed policies)", "severity": "POSITIVE",
            "evidence": f"Checkov ran {s.get('checkov_passed', 0)} passing policy(ies) with 0 failures "
                        f"against {s.get('checkov_input', 'the input')}.",
            "remediation": "Keep Checkov in CI; policy packs update regularly.", "cwe": "N/A"}


FINDING_RULES = [_r_binary] + [_mk(i) for i in range(60)] + [_r_clean]
INTEL_FIELDS = [("Scan input", "checkov_input"), ("Failed policies", "checkov_failed"),
                ("Passed policies", "checkov_passed"), ("By severity", "checkov_sev")]


@router.post("/api/vuln/checkov_iac_scan")
@vl_verify()
async def checkov_iac_scan(req: CheckovScanRequest, _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        await gather(ctx, iac_text=req.iac_text or "", filename=req.iac_filename or "",
                     repo_url=getattr(req, "repo_url", "") or "", target=req.target or "")
    return await run_scanner(host=(req.target or "iac-input"), tool="checkov_iac_scan",
                             gather_func=_gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
