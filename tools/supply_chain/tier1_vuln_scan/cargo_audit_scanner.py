"""cargo_audit_scanner - Rust dependency audit via cargo-audit (playbook §2 #21).

Matches a project's Cargo.lock against the RustSec advisory database. RUSTSEC
advisories are curated and authoritative, so a match is a confirmed vulnerable
crate (zero false positives). Also surfaces unmaintained / yanked crates.

osv_repo_audit gives broad multi-ecosystem coverage; this scanner adds the
Rust-native RustSec DB (richer Rust metadata: unmaintained/unsound/yanked
classes osv does not model).

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> find Cargo.lock)
  2. ScanRequest.target    (if it's a usable local path with Cargo.lock)
Image refs are not applicable (Cargo.lock is a source artifact).
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
from tools._payloads.cargo_audit_scanner_findings import CARGO_AUDIT_SCANNER_FINDING_RULES

router = APIRouter()
CARGO_AUDIT_BIN = shutil.which("cargo-audit") or "/usr/local/cargo/bin/cargo-audit"
CARGO_BIN = shutil.which("cargo") or "/usr/local/cargo/bin/cargo"
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


def _find_lockfile(root: str) -> str:
    """Find the first Cargo.lock within `root` (depth <= 3)."""
    root = root.rstrip("/")
    base_depth = root.count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base_depth > 3:
            dirnames[:] = []
            continue
        # skip vendored/hidden dirs
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "vendor", "node_modules")]
        if "Cargo.lock" in filenames:
            return os.path.join(dirpath, "Cargo.lock")
    return ""


def _audit_cmd(lockfile: str) -> list:
    if shutil.which("cargo-audit") or os.path.exists(CARGO_AUDIT_BIN):
        return [CARGO_AUDIT_BIN, "audit", "--json", "-f", lockfile]
    return [CARGO_BIN, "audit", "--json", "-f", lockfile]


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("cargo-audit") or os.path.exists(CARGO_AUDIT_BIN)
                or shutil.which("cargo") or os.path.exists(CARGO_BIN)):
            ctx.state["cargo_error"] = "cargo-audit binary not installed"
            ctx.source("cargo-audit missing")
            return

        cleanup_path = ""
        mode = ""
        scan_root = ""
        try:
            if repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="cargo_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["cargo_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_root = cleanup_path
                mode = "repo_url"
                ctx.state["cargo_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_root = target
                mode = "local_path"
                ctx.state["cargo_input_value"] = target
            else:
                ctx.state["cargo_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["cargo_input_mode"] = mode
            lockfile = _find_lockfile(scan_root)
            if not lockfile:
                ctx.state["cargo_no_lockfile"] = True
                ctx.source("no Cargo.lock")
                return
            ctx.state["cargo_lockfile"] = os.path.relpath(lockfile, scan_root)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *_audit_cmd(lockfile),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["cargo_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["cargo_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source(f"subprocess failed: {str(e)[:80]}")
                return

            # cargo-audit exits non-zero when advisories are found; JSON still
            # lands on stdout. Only treat empty stdout as a hard failure.
            if not stdout:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["cargo_error"] = f"cargo-audit rc={proc.returncode}: {err_text}"
                ctx.source(f"cargo-audit rc={proc.returncode}")
                return

            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["cargo_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            vulns = (data.get("vulnerabilities") or {})
            vlist = vulns.get("list") or []
            top = []
            for v in vlist:
                adv = v.get("advisory") or {}
                pkg = v.get("package") or {}
                top.append({"id": adv.get("id") or "?",
                            "title": (adv.get("title") or "")[:100],
                            "pkg": f"{pkg.get('name','?')}@{pkg.get('version','?')}"})

            warnings = data.get("warnings") or {}
            unmaintained, yanked = [], 0
            if isinstance(warnings, dict):
                for w in (warnings.get("unmaintained") or []):
                    pkg = (w.get("package") or {}).get("name")
                    if pkg:
                        unmaintained.append(pkg)
                yanked = len(warnings.get("yanked") or [])

            ctx.state["cargo_vuln_count"] = vulns.get("count") or len(vlist)
            ctx.state["cargo_top_vulns"] = top[:10]
            ctx.state["cargo_unmaintained"] = unmaintained[:15]
            ctx.state["cargo_unmaintained_count"] = len(unmaintained)
            ctx.state["cargo_yanked_count"] = yanked
            ctx.state["cargo_dependency_count"] = (
                (data.get("lockfile") or {}).get("dependency-count") or 0
            )
            ctx.source(f"cargo-audit: {ctx.state['cargo_vuln_count']} vuln(s), "
                       f"{len(unmaintained)} unmaintained, {yanked} yanked")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "cargo_input_mode"),
                ("Scan input", "cargo_input_value"),
                ("Lockfile", "cargo_lockfile"),
                ("Locked dependencies", "cargo_dependency_count"),
                ("Vulnerable crates", "cargo_vuln_count"),
                ("Top advisories", "cargo_top_vulns"),
                ("Unmaintained crates", "cargo_unmaintained"),
                ("Yanked versions", "cargo_yanked_count")]


@router.post("/api/supply_chain/cargo_audit_scanner")
async def supply_chain_cargo_audit_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="cargo_audit_scanner",
        gather_func=_make_gather(req),
        finding_rules=CARGO_AUDIT_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
