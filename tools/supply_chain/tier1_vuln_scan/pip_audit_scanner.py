"""pip_audit_scanner - Python dependency audit via pip-audit (playbook §2 SCA).

Matches a project's pinned requirements against the PyPI Advisory Database
(PYSEC) + OSV. A match is a confirmed vulnerable package (curated advisories =
zero false positives), and pip-audit reports the fix version. Complements
osv_repo_audit with Python-native resolution + remediation versions.

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> find requirements*.txt)
  2. ScanRequest.target    (local dir with requirements*.txt)
Image refs N/A (requirements are a source artifact).
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
from tools._payloads.pip_audit_scanner_findings import PIP_AUDIT_SCANNER_FINDING_RULES

router = APIRouter()
PIP_AUDIT_BIN = shutil.which("pip-audit") or "/usr/local/bin/pip-audit"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240


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


def _find_requirements(root: str) -> str:
    """First requirements*.txt within `root` (depth <= 3), preferring top-level."""
    root = root.rstrip("/")
    base = root.count(os.sep)
    cand = []
    for dp, dn, fn in os.walk(root):
        if dp.count(os.sep) - base > 3:
            dn[:] = []
            continue
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "venv", ".venv", "vendor", "__pycache__", "tests", "test")]
        for f in fn:
            if f == "requirements.txt" or (f.startswith("requirements") and f.endswith(".txt")):
                cand.append(os.path.join(dp, f))
    cand.sort(key=lambda p: (p.count(os.sep), os.path.basename(p) != "requirements.txt"))
    return cand[0] if cand else ""


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("pip-audit") or os.path.exists(PIP_AUDIT_BIN)):
            ctx.state["pip_error"] = "pip-audit binary not installed"
            ctx.source("pip-audit missing")
            return

        cleanup = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="pipaudit_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["pip_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                root = cleanup
                mode = "repo_url"
                ctx.state["pip_input_value"] = repo_url
            elif target and os.path.isdir(target):
                root = target
                mode = "local_path"
                ctx.state["pip_input_value"] = target
            else:
                ctx.state["pip_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["pip_input_mode"] = mode
            reqfile = _find_requirements(root)
            if not reqfile:
                ctx.state["pip_no_requirements"] = True
                ctx.source("no requirements.txt")
                return
            ctx.state["pip_requirements"] = os.path.relpath(reqfile, root)

            cmd = [PIP_AUDIT_BIN, "-r", reqfile, "-f", "json", "--progress-spinner", "off"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["pip_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["pip_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source("subprocess failed")
                return

            # pip-audit exits non-zero when vulns are found; JSON still on stdout.
            if not stdout:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["pip_error"] = f"pip-audit rc={proc.returncode}: {err_text}"
                ctx.source(f"pip-audit rc={proc.returncode}")
                return
            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["pip_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            deps = data.get("dependencies") if isinstance(data, dict) else (data or [])
            deps = deps or []
            top, vuln_pkgs = [], set()
            for d in deps:
                for v in (d.get("vulns") or []):
                    vuln_pkgs.add(d.get("name"))
                    top.append({"id": (v.get("id") or "?"),
                                "pkg": f"{d.get('name', '?')}@{d.get('version', '?')}",
                                "fix": ",".join(v.get("fix_versions") or [])})
            ctx.state["pip_vuln_count"] = len(top)
            ctx.state["pip_vuln_pkg_count"] = len(vuln_pkgs)
            ctx.state["pip_top_vulns"] = top[:10]
            ctx.state["pip_dependency_count"] = len(deps)
            ctx.source(f"pip-audit: {len(top)} vuln(s) across {len(vuln_pkgs)} pkg(s), {len(deps)} deps")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "pip_input_mode"),
                ("Scan input", "pip_input_value"),
                ("Requirements file", "pip_requirements"),
                ("Dependencies audited", "pip_dependency_count"),
                ("Vulnerabilities", "pip_vuln_count"),
                ("Vulnerable packages", "pip_vuln_pkg_count"),
                ("Top advisories", "pip_top_vulns")]


@router.post("/api/supply_chain/pip_audit_scanner")
async def supply_chain_pip_audit_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="pip_audit_scanner",
        gather_func=_make_gather(req),
        finding_rules=PIP_AUDIT_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
