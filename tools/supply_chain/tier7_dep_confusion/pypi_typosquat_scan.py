"""pypi_typosquat_scan - PyPI typosquat detection (playbook §3 #32).

Reads a project's declared Python dependencies and flags any whose name is
edit-distance 1 from a popular package (curated list) but is not that package.
Best-effort PyPI existence check escalates a near-miss that actually resolves
on PyPI (a live squat) to HIGH.

Pure-Python + a curated wordlist (tools/_payloads/supply_chain/) + an optional
PyPI JSON lookup. No external engine. Complements npm_dependency_confusion
(which covers the npm ecosystem).

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone)
  2. ScanRequest.target    (local path)
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
import urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.pypi_typosquat_scan_findings import PYPI_TYPOSQUAT_SCAN_FINDING_RULES
from tools._payloads.supply_chain._loader import load_lines

router = APIRouter()
GIT_BIN = shutil.which("git") or "/usr/bin/git"
# Minimal fallback so the scanner still functions if the curated list is absent
# (partial deploy / dev env). The full curated pool lives in
# tools/_payloads/supply_chain/pypi_top_packages.txt.
_TOP_LIST_FALLBACK = (
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi",
    "setuptools", "pip", "wheel", "boto3", "pyyaml", "cryptography", "click",
    "jinja2", "sqlalchemy", "pytest", "scipy", "pillow", "tensorflow", "torch",
)
_SKIP_DIRS = {".git", "target", "vendor", "node_modules", "dist", "build", ".venv"}
_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_MAX_PYPI_CHECKS = 12


def _load_top() -> set[str]:
    # VL-CORE loader (load_lines already strips blanks/# comments); normalize the
    # same way the original direct-read did: lowercase + underscores -> hyphens.
    try:
        out = set()
        for ln in load_lines("pypi_top_packages", fallback=_TOP_LIST_FALLBACK):
            ln = ln.strip().lower()
            if ln:
                out.add(ln.replace("_", "-"))
        return out
    except Exception:
        return {n.replace("_", "-") for n in _TOP_LIST_FALLBACK}


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _within_one(a: str, b: str) -> bool:
    """True iff a and b are one edit apart (Damerau-Levenshtein distance 1):
    a single substitution, insertion, deletion, OR adjacent transposition.
    Transpositions ('reqeusts' vs 'requests') are a top typosquat pattern, so
    they must count as distance 1 even though plain Levenshtein scores them 2."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:                      # single substitution
            return True
        if (len(diffs) == 2 and diffs[1] == diffs[0] + 1   # adjacent transposition
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]):
            return True
        return False
    # single insertion/deletion: walk both, allow one skip
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = 0
    edited = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1; j += 1
        else:
            if edited:
                return False
            edited = True
            j += 1  # skip one char in the longer string
    return True


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


def _find_files(root: str, names: tuple, patterns: tuple = ()) -> list[str]:
    root = root.rstrip("/")
    base = root.count(os.sep)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base > 4:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn in names or any(fn.startswith(p) and fn.endswith(".txt") for p in patterns):
                out.append(os.path.join(dirpath, fn))
    return out


def _extract_from_requirements(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        ln = line.strip()
        if not ln or ln.startswith("#") or ln.startswith("-"):
            continue
        ln = ln.split(";")[0].split("#")[0].strip()  # drop env markers / comments
        ln = ln.split("[")[0]  # drop extras
        m = _NAME_RE.match(ln)
        if m:
            out.add(_norm(m.group(1)))
    return out


def _extract_from_pyproject(text: str) -> set[str]:
    out = set()
    # PEP 621 dependencies = ["requests>=2", ...] and optional-deps arrays
    for arr in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.S):
        for q in re.findall(r"[\"']([^\"']+)[\"']", arr):
            m = _NAME_RE.match(q.split(";")[0].split("[")[0].strip())
            if m:
                out.add(_norm(m.group(1)))
    # Poetry [tool.poetry.dependencies] name = "version"
    sec = re.search(r"\[tool\.poetry\.dependencies\](.*?)(\n\[|\Z)", text, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r"^([A-Za-z0-9._-]+)\s*=", line.strip())
            if m and m.group(1).lower() != "python":
                out.add(_norm(m.group(1)))
    return out


def _pypi_exists(name: str) -> bool:
    try:
        req = urllib.request.Request(
            f"https://pypi.org/pypi/{name}/json",
            headers={"User-Agent": "VulnusLab-supply-chain/1.0"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            return resp.status == 200
    except Exception:
        return False


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        top = _load_top()
        if not top:
            ctx.state["typo_error"] = "curated PyPI top-list missing"
            ctx.source("top-list missing")
            return

        cleanup_path = ""
        scan_root = ""
        mode = ""
        try:
            if repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="typo_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["typo_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_root = cleanup_path
                mode = "repo_url"
                ctx.state["typo_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_root = target
                mode = "local_path"
                ctx.state["typo_input_value"] = target
            else:
                ctx.state["typo_no_input"] = True
                ctx.source("repo_url or local path required")
                return
            ctx.state["typo_input_mode"] = mode

            declared: set[str] = set()
            for p in _find_files(scan_root, ("requirements.txt",), patterns=("requirements",)):
                declared |= _extract_from_requirements(
                    open(p, "r", encoding="utf-8", errors="ignore").read(2_000_000))
            for p in _find_files(scan_root, ("pyproject.toml", "setup.py")):
                declared |= _extract_from_pyproject(
                    open(p, "r", encoding="utf-8", errors="ignore").read(2_000_000))

            if not declared:
                ctx.state["typo_no_requirements"] = True
                ctx.source("no python manifest")
                return

            ctx.state["typo_declared_count"] = len(declared)

            # Candidates = declared names not in the popular list that are
            # edit-distance 1 from a popular name.
            candidates = []
            for name in sorted(declared):
                if name in top:
                    continue
                near = next((t for t in top if _within_one(name, t)), None)
                if near:
                    candidates.append({"declared": name, "near": near, "exists_on_pypi": False})

            # Best-effort PyPI existence escalation (capped, non-fatal).
            checks = 0
            for c in candidates:
                if checks >= _MAX_PYPI_CHECKS:
                    break
                checks += 1
                try:
                    c["exists_on_pypi"] = await asyncio.to_thread(_pypi_exists, c["declared"])
                except Exception:
                    c["exists_on_pypi"] = False

            ctx.state["typo_candidates"] = candidates
            ctx.source(f"typosquat: {len(declared)} declared deps, {len(candidates)} near-miss candidate(s)")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "typo_input_mode"),
                ("Scan input", "typo_input_value"),
                ("Declared dependencies", "typo_declared_count"),
                ("Typosquat candidates", "typo_candidates")]


@router.post("/api/supply_chain/pypi_typosquat_scan")
async def supply_chain_pypi_typosquat_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="pypi_typosquat_scan",
        gather_func=_make_gather(req),
        finding_rules=PYPI_TYPOSQUAT_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
