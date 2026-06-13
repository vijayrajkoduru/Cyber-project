"""transitive_dependency_depth - dependency-graph surface metric (playbook §2 #28).

Pure lockfile analysis (no external engine). Parses the common lockfiles in a
source tree and computes direct vs transitive dependency counts and, where the
format allows, the maximum nesting depth. A large transitive:direct ratio is
where dependency-confusion / typosquatting hides, so this is a useful
risk-surface signal — emitted as INFO/LOW advisory (zero false positives,
it is just counting).

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone)
  2. ScanRequest.target    (local path)
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.transitive_dependency_depth_findings import TRANSITIVE_DEPENDENCY_DEPTH_FINDING_RULES

router = APIRouter()
GIT_BIN = shutil.which("git") or "/usr/bin/git"
_SKIP_DIRS = {".git", "target", "vendor", "node_modules", "dist", "build", ".venv"}


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


def _find_files(root: str, names: tuple) -> list[str]:
    root = root.rstrip("/")
    base = root.count(os.sep)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base > 4:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn in names:
                out.append(os.path.join(dirpath, fn))
    return out


def _read(path: str, limit: int = 4_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def _parse_npm_lock(path: str) -> tuple[int, int, int, int]:
    """Return (direct, transitive, total, max_nesting) for an npm lockfile."""
    raw = _read(path)
    if not raw:
        return 0, 0, 0, 0
    try:
        data = json.loads(raw)
    except Exception:
        return 0, 0, 0, 0
    pkgs = data.get("packages")
    if isinstance(pkgs, dict) and pkgs:
        # lockfileVersion 2/3: flat map keyed by node_modules paths.
        root = pkgs.get("") or {}
        direct = len(root.get("dependencies") or {}) + len(root.get("devDependencies") or {})
        total = 0
        max_nest = 0
        for key in pkgs:
            if not key:
                continue
            total += 1
            max_nest = max(max_nest, key.count("node_modules/"))
        transitive = max(0, total - direct)
        return direct, transitive, total, max_nest
    # lockfileVersion 1: recurse the nested "dependencies" tree.
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        total = [0]
        def walk(node, depth):
            d = node.get("dependencies") if isinstance(node, dict) else None
            md = depth
            if isinstance(d, dict):
                for v in d.values():
                    total[0] += 1
                    md = max(md, walk(v, depth + 1))
            return md
        max_nest = walk({"dependencies": deps}, 0)
        direct = len(deps)
        return direct, max(0, total[0] - direct), total[0], max_nest
    return 0, 0, 0, 0


def _parse_go_mod(path: str) -> tuple[int, int, int, int]:
    raw = _read(path)
    direct = indirect = 0
    in_block = False
    for line in raw.splitlines():
        ln = line.strip()
        if ln.startswith("require ("):
            in_block = True
            continue
        if in_block and ln == ")":
            in_block = False
            continue
        is_req = in_block or ln.startswith("require ")
        if not is_req:
            continue
        body = ln[len("require "):].strip() if ln.startswith("require ") else ln
        if not body or body.startswith("//"):
            continue
        if "// indirect" in line:
            indirect += 1
        else:
            direct += 1
    total = direct + indirect
    return direct, indirect, total, 0


def _parse_gemfile_lock(path: str) -> tuple[int, int, int, int]:
    raw = _read(path)
    direct = total = 0
    section = ""
    for line in raw.splitlines():
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if section == "DEPENDENCIES" and line.startswith("  ") and line.strip():
            direct += 1
        # GEM/specs: two-space indent = a package, four-space = its deps
        if section == "GEM" and re.match(r"^    [a-zA-Z0-9]", line):
            total += 1
    return direct, max(0, total - direct), total, 0


def _count_toml_packages(path: str) -> int:
    raw = _read(path)
    return len(re.findall(r"^\[\[package\]\]", raw, re.M))


def _count_lines_pkgs(path: str) -> int:
    raw = _read(path)
    n = 0
    for line in raw.splitlines():
        ln = line.strip()
        if not ln or ln.startswith("#") or ln.startswith("-"):
            continue
        n += 1
    return n


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        cleanup_path = ""
        scan_root = ""
        mode = ""
        try:
            if repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="depth_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["depth_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_root = cleanup_path
                mode = "repo_url"
                ctx.state["depth_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_root = target
                mode = "local_path"
                ctx.state["depth_input_value"] = target
            else:
                ctx.state["depth_no_input"] = True
                ctx.source("repo_url or local path required")
                return
            ctx.state["depth_input_mode"] = mode

            direct = transitive = total = max_nest = 0
            ecos = []

            for p in _find_files(scan_root, ("package-lock.json",)):
                d, t, tot, mn = _parse_npm_lock(p)
                if tot:
                    direct += d; transitive += t; total += tot
                    max_nest = max(max_nest, mn)
                    if "npm" not in ecos: ecos.append("npm")
            for p in _find_files(scan_root, ("go.mod",)):
                d, t, tot, _ = _parse_go_mod(p)
                if tot:
                    direct += d; transitive += t; total += tot
                    if "go" not in ecos: ecos.append("go")
            for p in _find_files(scan_root, ("Gemfile.lock",)):
                d, t, tot, _ = _parse_gemfile_lock(p)
                if tot:
                    direct += d; transitive += t; total += tot
                    if "rubygems" not in ecos: ecos.append("rubygems")
            for p in _find_files(scan_root, ("Cargo.lock", "poetry.lock")):
                n = _count_toml_packages(p)
                if n:
                    total += n; transitive += n
                    eco = "cargo" if p.endswith("Cargo.lock") else "poetry"
                    if eco not in ecos: ecos.append(eco)
            for p in _find_files(scan_root, ("requirements.txt",)):
                n = _count_lines_pkgs(p)
                if n:
                    direct += n; total += n
                    if "pip" not in ecos: ecos.append("pip")

            if total <= 0:
                ctx.state["depth_no_lockfile"] = True
                ctx.source("no lockfile")
                return

            ctx.state["depth_direct"] = direct
            ctx.state["depth_transitive"] = transitive
            ctx.state["depth_total"] = total
            ctx.state["depth_max_nesting"] = max_nest
            ctx.state["depth_ecosystems"] = ecos
            ctx.source(f"deps: {total} total ({direct} direct / {transitive} transitive) "
                       f"across {len(ecos)} ecosystem(s), max nesting {max_nest}")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "depth_input_mode"),
                ("Scan input", "depth_input_value"),
                ("Ecosystems", "depth_ecosystems"),
                ("Direct dependencies", "depth_direct"),
                ("Transitive dependencies", "depth_transitive"),
                ("Total dependencies", "depth_total"),
                ("Max nesting depth", "depth_max_nesting")]


@router.post("/api/supply_chain/transitive_dependency_depth")
async def supply_chain_transitive_dependency_depth(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="transitive_dependency_depth",
        gather_func=_make_gather(req),
        finding_rules=TRANSITIVE_DEPENDENCY_DEPTH_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
