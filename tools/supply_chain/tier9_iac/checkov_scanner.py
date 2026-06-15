"""checkov_scanner - Infrastructure-as-Code misconfiguration scan via Checkov.

Clones a repo and runs Checkov across every IaC framework it detects —
Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm, ARM,
Serverless, GitHub Actions. Each failed check is a real, rule-backed
misconfiguration (curated Checkov policies; not a heuristic), so findings are
high-confidence. Complements the dependency SCA scanners with infra-layer
coverage.

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> scan IaC in the tree)
  2. ScanRequest.target    (local dir with IaC)
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
from tools._payloads.checkov_scanner_findings import CHECKOV_SCANNER_FINDING_RULES

router = APIRouter()
CHECKOV_BIN = shutil.which("checkov") or "/usr/local/bin/checkov"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 300


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


def _parse_checkov(data):
    """Checkov -o json is a single object or a list (one per framework).
    Returns (failed_total, passed_total, sev_counts, top[])."""
    frameworks = data if isinstance(data, list) else [data]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    failed_total = passed_total = 0
    top = []
    for fw in frameworks:
        if not isinstance(fw, dict):
            continue
        res = fw.get("results") or {}
        fc = res.get("failed_checks") or []
        summ = fw.get("summary") or {}
        failed_total += int(summ.get("failed") or len(fc))
        passed_total += int(summ.get("passed") or 0)
        for c in fc:
            sev = c.get("severity")
            sev = sev.upper() if isinstance(sev, str) else "UNKNOWN"
            if sev not in sev_counts:
                sev = "UNKNOWN"
            sev_counts[sev] += 1
            if len(top) < 12:
                top.append({"id": c.get("check_id") or "?",
                            "name": (c.get("check_name") or "")[:80],
                            "file": c.get("file_path") or "?",
                            "sev": sev})
    return failed_total, passed_total, sev_counts, top


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("checkov") or os.path.exists(CHECKOV_BIN)):
            ctx.state["ckv_error"] = "checkov binary not installed"
            ctx.source("checkov missing")
            return

        cleanup = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="checkov_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["ckv_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                root = cleanup
                mode = "repo_url"
                ctx.state["ckv_input_value"] = repo_url
            elif target and os.path.isdir(target):
                root = target
                mode = "local_path"
                ctx.state["ckv_input_value"] = target
            else:
                ctx.state["ckv_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["ckv_input_mode"] = mode
            cmd = [CHECKOV_BIN, "-d", root, "-o", "json", "--compact", "--quiet"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["ckv_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["ckv_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source("subprocess failed")
                return

            # Checkov exits non-zero when checks fail; JSON still on stdout.
            if not stdout:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["ckv_error"] = f"checkov rc={proc.returncode}: {err_text}"
                ctx.source(f"checkov rc={proc.returncode}")
                return
            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["ckv_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            failed, passed, sev_counts, top = _parse_checkov(data)
            if failed == 0 and passed == 0:
                ctx.state["ckv_no_iac"] = True
                ctx.source("no IaC detected")
                return

            ctx.state["ckv_failed"] = failed
            ctx.state["ckv_passed"] = passed
            ctx.state["ckv_sev_counts"] = sev_counts
            ctx.state["ckv_top"] = top
            ctx.source(f"checkov: {failed} failed / {passed} passed "
                       f"(C{sev_counts['CRITICAL']}/H{sev_counts['HIGH']}/M{sev_counts['MEDIUM']})")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "ckv_input_mode"),
                ("Scan input", "ckv_input_value"),
                ("Failed checks", "ckv_failed"),
                ("Passed checks", "ckv_passed"),
                ("By severity", "ckv_sev_counts"),
                ("Top misconfigurations", "ckv_top")]


@router.post("/api/supply_chain/checkov_scanner")
async def supply_chain_checkov_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="checkov_scanner",
        gather_func=_make_gather(req),
        finding_rules=CHECKOV_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
