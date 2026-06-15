"""tfsec Terraform scan — real engine (Vuln tier9 §9, Terraform specialist).

tfsec is a Terraform-focused static analyzer (now part of Trivy, but the
standalone binary is in the image). Complements checkov_iac_scan (broad,
multi-framework) with deep Terraform/HCL coverage and clean rule IDs.

Customer input precedence:
  1. ScanRequest.iac_text  -> written as ./main.tf, scanned
  2. ScanRequest.repo_url  -> shallow clone, scanned recursively
  3. ScanRequest.target    -> existing local dir

Zero false positives: each finding is a tfsec result with its rule id, severity,
file/line, and resolution. NOT-APPLICABLE skip when no Terraform input.
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
TFSEC_BIN = shutil.which("tfsec") or "/usr/local/bin/tfsec"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240


class TfsecScanRequest(ScanRequest):
    iac_text: Optional[str] = None
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


async def gather(ctx, *, iac_text="", repo_url="", target=""):
    if not (shutil.which("tfsec") or os.path.exists(TFSEC_BIN)):
        ctx.state["tfsec_error"] = "tfsec binary not installed"
        ctx.source("tfsec missing")
        return

    cleanup = ""
    scan_dir = ""
    try:
        if (iac_text or "").strip():
            cleanup = tempfile.mkdtemp(prefix="tfsec_")
            with open(os.path.join(cleanup, "main.tf"), "w", encoding="utf-8") as fh:
                fh.write(iac_text)
            scan_dir = cleanup
            ctx.state["tfsec_input"] = f"pasted {len(iac_text)} bytes (main.tf)"
        elif (repo_url or "").strip():
            cleanup = tempfile.mkdtemp(prefix="tfsec_repo_")
            ok, err = await _shallow_clone(repo_url, cleanup)
            if not ok:
                ctx.state["tfsec_error"] = err
                ctx.source(f"clone failed: {err}")
                return
            scan_dir = cleanup
            ctx.state["tfsec_input"] = repo_url
        elif target and os.path.isdir(target):
            scan_dir = target
            ctx.state["tfsec_input"] = target
        else:
            ctx.state["skipped_reason"] = (
                "No Terraform provided. Paste HCL into iac_text or pass repo_url to run tfsec."
            )
            return

        ctx.source("tfsec")
        cmd = [TFSEC_BIN, scan_dir, "--format", "json", "--no-color", "--soft-fail"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                ctx.state["tfsec_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except Exception as e:
            ctx.state["tfsec_error"] = f"subprocess: {str(e)[:120]}"
            ctx.source("subprocess failed")
            return

        if not stdout:
            err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            ctx.state["tfsec_error"] = f"tfsec rc={proc.returncode}: {err}"
            ctx.source(f"tfsec rc={proc.returncode}")
            return
        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            ctx.state["tfsec_error"] = f"json parse: {str(e)[:120]}"
            ctx.source("bad json")
            return

        results = data.get("results") or []
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        items = []
        for r in results:
            sev = (r.get("severity") or "MEDIUM").upper()
            if sev not in by_sev:
                sev = "MEDIUM"
            by_sev[sev] += 1
            loc = r.get("location") or {}
            items.append({
                "id": r.get("rule_id") or r.get("long_id") or "tfsec",
                "desc": (r.get("description") or r.get("rule_description") or "")[:160],
                "severity": sev,
                "file": (loc.get("filename") or "")[:120],
                "line": loc.get("start_line"),
                "resolution": (r.get("resolution") or "")[:300],
            })
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        items.sort(key=lambda x: (order.get(x["severity"], 9), x["id"]))
        ctx.state["tfsec_items"] = items
        ctx.state["tfsec_failed"] = len(items)
        ctx.state["tfsec_sev"] = by_sev
        ctx.source(f"tfsec: {len(items)} Terraform issue(s)")
    finally:
        if cleanup:
            try:
                shutil.rmtree(cleanup, ignore_errors=True)
            except Exception:
                pass


def _mk(i):
    def rule(s):
        items = s.get("tfsec_items") or []
        if i >= len(items):
            return None
        it = items[i]
        loc = it["file"] + (f" L{it['line']}" if it.get("line") else "")
        return {"name": f"{it['id']}: {it['desc']}",
                "severity": it["severity"], "cwe": "CWE-1008",
                "evidence": f"tfsec flagged this in {loc}.",
                "remediation": it.get("resolution") or "Remediate per the tfsec rule guidance."}
    return rule


def _r_binary(s):
    err = s.get("tfsec_error") or ""
    if "tfsec binary not installed" not in err:
        return None
    return {"name": "tfsec not installed", "severity": "INFO", "evidence": err,
            "remediation": "Install tfsec in the scanner image.", "cwe": "N/A"}


def _r_clean(s):
    if s.get("tfsec_items") is None or s.get("tfsec_error"):
        return None
    if s.get("tfsec_items"):
        return None
    return {"name": "tfsec clean (no Terraform issues)", "severity": "POSITIVE",
            "evidence": f"tfsec found 0 issues in {s.get('tfsec_input', 'the input')}.",
            "remediation": "Keep tfsec/trivy in CI for Terraform.", "cwe": "N/A"}


FINDING_RULES = [_r_binary] + [_mk(i) for i in range(60)] + [_r_clean]
INTEL_FIELDS = [("Scan input", "tfsec_input"), ("Issues", "tfsec_failed"), ("By severity", "tfsec_sev")]


@router.post("/api/vuln/tfsec_terraform_scan")
@vl_verify()
async def tfsec_terraform_scan(req: TfsecScanRequest, _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        await gather(ctx, iac_text=req.iac_text or "", repo_url=getattr(req, "repo_url", "") or "",
                     target=req.target or "")
    return await run_scanner(host=(req.target or "iac-input"), tool="tfsec_terraform_scan",
                             gather_func=_gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
