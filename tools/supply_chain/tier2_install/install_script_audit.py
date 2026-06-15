"""install_script_audit - install/build-time script behavior audit (playbook §3).

ADVISORY-ONLY. Reads a project's install/build manifests (setup.py, setup.cfg,
pyproject.toml, package.json pre/post/install lifecycle scripts) and matches
their text against the curated suspicious-install-script pattern set
(tools/_payloads/supply_chain/install_script_patterns.json). Each pattern is a
HEURISTIC for human review — many legitimate packages match — so findings are
graded INFO or LOW ONLY (taken from the pattern's own severity, hard-capped so
nothing ever escalates to HIGH/CRITICAL). This is detection-for-review, not
exploitation: we report only that a known-suspicious pattern literally matched.

Pure-Python + a curated JSON pattern set. No external engine.

Customer input precedence (same honest modes as pypi_typosquat_scan):
  1. ScanRequest.repo_url  (shallow clone)
  2. ScanRequest.target    (local path)
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.install_script_audit_findings import INSTALL_SCRIPT_AUDIT_FINDING_RULES
from tools._payloads.supply_chain._loader import load_json

router = APIRouter()
GIT_BIN = shutil.which("git") or "/usr/bin/git"
_SKIP_DIRS = {".git", "target", "vendor", "node_modules", "dist", "build", ".venv"}
# Install/build manifests we audit. package.json is included for npm lifecycle
# scripts; for package.json we restrict matching to its "scripts" block so we
# only flag install-time hooks, not arbitrary app code.
_PY_MANIFESTS = ("setup.py", "setup.cfg", "pyproject.toml")
_NPM_MANIFEST = "package.json"
_MAX_FILE_BYTES = 2_000_000
_ADVISORY_SEVERITIES = {"INFO", "LOW"}
# Lifecycle keys whose contents are install/build-time hooks worth auditing.
_NPM_LIFECYCLE_KEYS = {"preinstall", "install", "postinstall", "preuninstall",
                       "postuninstall", "prepare", "prepublish", "prepublishOnly",
                       "preprepare", "postprepare", "prepack", "postpack"}


def _load_patterns() -> list[dict]:
    """Load + compile curated install-script patterns. Bad/over-severe entries
    are sanitized: severity is hard-capped to INFO/LOW; uncompilable regex is
    dropped (never raises)."""
    raw = load_json("install_script_patterns", fallback={})
    pats = raw.get("patterns") if isinstance(raw, dict) else None
    if not isinstance(pats, list):
        return []
    out = []
    for p in pats:
        if not isinstance(p, dict):
            continue
        rx = p.get("regex")
        name = p.get("name") or "unnamed-pattern"
        if not rx:
            continue
        sev = (p.get("severity") or "INFO").upper()
        if sev not in _ADVISORY_SEVERITIES:   # advisory hard cap, never HIGH/CRITICAL
            sev = "LOW"
        try:
            cre = re.compile(rx, re.IGNORECASE)
        except re.error:
            continue
        out.append({"name": name, "re": cre, "severity": sev,
                    "note": p.get("note") or ""})
    return out


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


def _find_manifests(root: str) -> list[str]:
    root = root.rstrip("/").rstrip("\\")
    base = root.count(os.sep)
    wanted = set(_PY_MANIFESTS) | {_NPM_MANIFEST}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base > 4:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn in wanted:
                out.append(os.path.join(dirpath, fn))
    return out


def _npm_script_text(text: str) -> str:
    """For package.json, return only the install/build lifecycle hook commands so
    we audit install-time scripts, not arbitrary application code. Falls back to
    the whole file if the JSON cannot be parsed (so npm-* regexes still see the
    raw "preinstall": "..." literals they are written against)."""
    import json as _json
    try:
        data = _json.loads(text)
    except Exception:
        return text
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return ""
    chunks = []
    for k, v in scripts.items():
        if k in _NPM_LIFECYCLE_KEYS and isinstance(v, str):
            # Reconstruct the "key": "value" literal so the curated npm-* regexes
            # (which match the JSON key/value shape) apply correctly.
            chunks.append(f'"{k}": "{v}"')
    return "\n".join(chunks)


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except Exception:
        return os.path.basename(path)


def _scan_manifest(root: str, path: str, patterns: list[dict]) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(_MAX_FILE_BYTES)
    except OSError:
        return []
    base = os.path.basename(path)
    if base == _NPM_MANIFEST:
        text = _npm_script_text(text)
        if not text.strip():
            return []
    rel = _rel(root, path)
    hits = []
    for p in patterns:
        if p["re"].search(text):
            hits.append({"pattern": p["name"], "file": rel,
                         "severity": p["severity"], "note": p["note"]})
    return hits


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        patterns = _load_patterns()
        if not patterns:
            ctx.state["isa_patterns_missing"] = True
            ctx.source("curated install-script patterns missing")
            return

        cleanup_path = ""
        scan_root = ""
        mode = ""
        try:
            if repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="isa_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["isa_clone_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_root = cleanup_path
                mode = "repo_url"
                ctx.state["isa_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_root = target
                mode = "local_path"
                ctx.state["isa_input_value"] = target
            else:
                ctx.state["isa_no_input"] = True
                ctx.source("repo_url or local path required")
                return
            ctx.state["isa_input_mode"] = mode

            manifests = _find_manifests(scan_root)
            ctx.state["isa_manifest_count"] = len(manifests)
            if not manifests:
                ctx.state["isa_no_manifests"] = True
                ctx.source("no install/build manifest")
                return

            hits: list[dict] = []
            for p in manifests:
                hits.extend(await asyncio.to_thread(_scan_manifest, scan_root, p, patterns))

            ctx.state["isa_hits"] = hits
            ctx.state["isa_manifests"] = [_rel(scan_root, p) for p in manifests][:40]
            ctx.source(f"install-script audit: {len(manifests)} manifest(s), "
                       f"{len(hits)} advisory pattern hit(s)")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "isa_input_mode"),
                ("Scan input", "isa_input_value"),
                ("Manifests audited", "isa_manifest_count"),
                ("Manifest files", "isa_manifests"),
                ("Advisory pattern hits", "isa_hits")]


@router.post("/api/supply_chain/install_script_audit")
async def supply_chain_install_script_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="install_script_audit",
        gather_func=_make_gather(req),
        finding_rules=INSTALL_SCRIPT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
