"""Trivy config audit — Dockerfile / IaC misconfiguration + CIS checks (Vuln tier8).

Runs `trivy config` (Aqua Trivy's misconfiguration scanner) over a Dockerfile,
Kubernetes manifest, or Terraform — surfacing Dockerfile security checks
(run-as-root, no HEALTHCHECK, ADD vs COPY, etc.) and built-in CIS / AVD policies
with real severities. Fills the previously-empty container-config tier.

Customer input precedence:
  1. ScanRequest.dockerfile_text -> written as ./Dockerfile and scanned
  2. ScanRequest.iac_text        -> written and scanned
  3. ScanRequest.repo_url        -> shallow clone, scanned recursively
  4. ScanRequest.target          -> existing local dir

Zero false positives: each finding is a Trivy misconfiguration with its AVD/DS
id, severity, line, and resolution. NOT-APPLICABLE skip when no input.
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
TRIVY_BIN = shutil.which("trivy") or "/usr/local/bin/trivy"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240


class TrivyConfigRequest(ScanRequest):
    dockerfile_text: Optional[str] = None
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


async def gather(ctx, *, dockerfile_text="", iac_text="", filename="", repo_url="", target=""):
    if not (shutil.which("trivy") or os.path.exists(TRIVY_BIN)):
        ctx.state["trivy_error"] = "trivy binary not installed"
        ctx.source("trivy missing")
        return

    cleanup = ""
    scan_dir = ""
    try:
        if (dockerfile_text or "").strip():
            cleanup = tempfile.mkdtemp(prefix="trivycfg_df_")
            with open(os.path.join(cleanup, "Dockerfile"), "w", encoding="utf-8") as fh:
                fh.write(dockerfile_text)
            scan_dir = cleanup
            ctx.state["trivy_input"] = f"pasted Dockerfile ({len(dockerfile_text)} bytes)"
        elif (iac_text or "").strip():
            cleanup = tempfile.mkdtemp(prefix="trivycfg_iac_")
            with open(os.path.join(cleanup, os.path.basename(filename or "main.tf")), "w", encoding="utf-8") as fh:
                fh.write(iac_text)
            scan_dir = cleanup
            ctx.state["trivy_input"] = f"pasted IaC ({len(iac_text)} bytes)"
        elif (repo_url or "").strip():
            cleanup = tempfile.mkdtemp(prefix="trivycfg_repo_")
            ok, err = await _shallow_clone(repo_url, cleanup)
            if not ok:
                ctx.state["trivy_error"] = err
                ctx.source(f"clone failed: {err}")
                return
            scan_dir = cleanup
            ctx.state["trivy_input"] = repo_url
        elif target and os.path.isdir(target):
            scan_dir = target
            ctx.state["trivy_input"] = target
        else:
            ctx.state["skipped_reason"] = (
                "No config provided. Paste a Dockerfile into dockerfile_text (or IaC into "
                "iac_text), or pass repo_url, to run Trivy config."
            )
            return

        ctx.source("trivy-config")
        cmd = [TRIVY_BIN, "config", scan_dir, "--format", "json", "--quiet"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                ctx.state["trivy_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except Exception as e:
            ctx.state["trivy_error"] = f"subprocess: {str(e)[:120]}"
            ctx.source("subprocess failed")
            return

        if not stdout:
            err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            ctx.state["trivy_error"] = f"trivy rc={proc.returncode}: {err}"
            ctx.source(f"trivy rc={proc.returncode}")
            return
        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            ctx.state["trivy_error"] = f"json parse: {str(e)[:120]}"
            ctx.source("bad json")
            return

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        items = []
        for r in (data.get("Results") or []):
            tgt = r.get("Target") or "?"
            for m in (r.get("Misconfigurations") or []):
                sev = (m.get("Severity") or "MEDIUM").upper()
                if sev not in by_sev:
                    sev = "MEDIUM"
                by_sev[sev] += 1
                cm = m.get("CauseMetadata") or {}
                items.append({
                    "id": m.get("ID") or m.get("AVDID") or "TRIVY",
                    "title": (m.get("Title") or "")[:140],
                    "severity": sev,
                    "target": tgt[:120],
                    "line": cm.get("StartLine"),
                    "resolution": (m.get("Resolution") or "")[:300],
                })
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        items.sort(key=lambda x: (order.get(x["severity"], 9), x["id"]))
        ctx.state["trivy_items"] = items
        ctx.state["trivy_failed"] = len(items)
        ctx.state["trivy_sev"] = by_sev
        ctx.source(f"trivy config: {len(items)} misconfiguration(s)")
    finally:
        if cleanup:
            try:
                shutil.rmtree(cleanup, ignore_errors=True)
            except Exception:
                pass


def _mk(i):
    def rule(s):
        items = s.get("trivy_items") or []
        if i >= len(items):
            return None
        it = items[i]
        loc = it["target"] + (f" L{it['line']}" if it.get("line") else "")
        return {"name": f"{it['id']}: {it['title']}",
                "severity": it["severity"], "cwe": "CWE-1008",
                "evidence": f"Trivy config misconfiguration in {loc}.",
                "remediation": it.get("resolution") or "Remediate per the Trivy/AVD policy for this id."}
    return rule


def _r_binary(s):
    err = s.get("trivy_error") or ""
    if "trivy binary not installed" not in err:
        return None
    return {"name": "trivy not installed", "severity": "INFO", "evidence": err,
            "remediation": "Install trivy in the scanner image.", "cwe": "N/A"}


def _r_clean(s):
    if s.get("trivy_items") is None or s.get("trivy_error"):
        return None
    if s.get("trivy_items"):
        return None
    return {"name": "Trivy config clean (no misconfigurations)", "severity": "POSITIVE",
            "evidence": f"Trivy config found 0 misconfigurations in {s.get('trivy_input', 'the input')}.",
            "remediation": "Keep `trivy config` in CI; the policy DB updates regularly.", "cwe": "N/A"}


FINDING_RULES = [_r_binary] + [_mk(i) for i in range(60)] + [_r_clean]
INTEL_FIELDS = [("Scan input", "trivy_input"), ("Misconfigurations", "trivy_failed"),
                ("By severity", "trivy_sev")]


@router.post("/api/vuln/trivy_config_audit")
@vl_verify()
async def trivy_config_audit(req: TrivyConfigRequest, _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        await gather(ctx, dockerfile_text=getattr(req, "dockerfile_text", "") or "",
                     iac_text=req.iac_text or "", filename=req.iac_filename or "",
                     repo_url=getattr(req, "repo_url", "") or "", target=req.target or "")
    return await run_scanner(host=(req.target or "config-input"), tool="trivy_config_audit",
                             gather_func=_gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
