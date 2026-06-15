"""govulncheck_scanner - Go dependency vuln scan via govulncheck (playbook §2 #20).

Queries the Go vulnerability database (vuln.go.dev / OSV) against a Go module.
Unlike a generic SCA, govulncheck does call-graph REACHABILITY analysis — it
distinguishes vulns whose affected code your module actually CALLS (high
priority) from vulns merely present in the dependency graph (lower priority).

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> find go.mod)
  2. ScanRequest.target    (local path with go.mod)

NOTE: govulncheck JSON is a stream of objects (config/progress/osv/finding);
parsed here with a raw_decode loop. Validate against a real Go repo on the VPS.
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
from tools._payloads.govulncheck_scanner_findings import GOVULNCHECK_SCANNER_FINDING_RULES

router = APIRouter()
GOVULN_BIN = shutil.which("govulncheck") or "/usr/local/bin/govulncheck"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 300


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


def _find_module_dir(root: str) -> str:
    root = root.rstrip("/")
    base = root.count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - base > 3:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in (".git", "vendor", "node_modules")]
        if "go.mod" in filenames:
            return dirpath
    return ""


def _parse_stream(text: str):
    """govulncheck -json emits concatenated JSON objects; decode them all."""
    dec = json.JSONDecoder()
    out = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(text, i)
        except Exception:
            break
        out.append(obj)
        i = end
    return out


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("govulncheck") or os.path.exists(GOVULN_BIN)):
            ctx.state["govuln_error"] = "govulncheck binary not installed"
            ctx.source("govulncheck missing")
            return

        cleanup = ""
        scan_root = ""
        mode = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="govuln_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["govuln_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_root = cleanup
                mode = "repo_url"
                ctx.state["govuln_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_root = target
                mode = "local_path"
                ctx.state["govuln_input_value"] = target
            else:
                ctx.state["govuln_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["govuln_input_mode"] = mode
            mod_dir = _find_module_dir(scan_root)
            if not mod_dir:
                ctx.state["govuln_no_gomod"] = True
                ctx.source("no go.mod")
                return

            try:
                proc = await asyncio.create_subprocess_exec(
                    GOVULN_BIN, "-json", "./...",
                    cwd=mod_dir,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "GOFLAGS": "-mod=mod"},
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["govuln_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["govuln_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source("subprocess failed")
                return

            if not stdout:
                err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["govuln_error"] = f"govulncheck rc={proc.returncode}: {err}"
                ctx.source(f"govulncheck rc={proc.returncode}")
                return

            objs = _parse_stream(stdout.decode("utf-8", errors="ignore"))
            osv_summary = {}     # id -> summary
            vuln_called = {}     # id -> bool (reachable)
            vuln_module = {}     # id -> module name
            for o in objs:
                if not isinstance(o, dict):
                    continue
                if "osv" in o and isinstance(o["osv"], dict):
                    rec = o["osv"]
                    osv_summary[rec.get("id")] = (rec.get("summary") or "")[:140]
                elif "finding" in o and isinstance(o["finding"], dict):
                    f = o["finding"]
                    oid = f.get("osv")
                    if not oid:
                        continue
                    trace = f.get("trace") or []
                    top = trace[0] if trace else {}
                    called = bool(top.get("function"))
                    vuln_called[oid] = vuln_called.get(oid, False) or called
                    if top.get("module"):
                        vuln_module[oid] = top.get("module")

            called = [{"id": k, "module": vuln_module.get(k, "?"),
                       "summary": osv_summary.get(k, ""), "called": True}
                      for k, v in vuln_called.items() if v]
            imported = [{"id": k, "module": vuln_module.get(k, "?"),
                         "summary": osv_summary.get(k, ""), "called": False}
                        for k, v in vuln_called.items() if not v]

            ctx.state["govuln_called_count"] = len(called)
            ctx.state["govuln_imported_count"] = len(imported)
            ctx.state["govuln_top"] = (called + imported)[:10]
            ctx.source(f"govulncheck: {len(called)} reachable, {len(imported)} imported-only")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "govuln_input_mode"),
                ("Scan input", "govuln_input_value"),
                ("Reachable vulns", "govuln_called_count"),
                ("Imported-only vulns", "govuln_imported_count"),
                ("Top vulns", "govuln_top")]


@router.post("/api/supply_chain/govulncheck_scanner")
async def supply_chain_govulncheck_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="govulncheck_scanner",
        gather_func=_make_gather(req),
        finding_rules=GOVULNCHECK_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
