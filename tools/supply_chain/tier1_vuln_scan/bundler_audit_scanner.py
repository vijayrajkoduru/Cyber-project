"""bundler_audit_scanner - Ruby dependency audit via bundler-audit (playbook §2 SCA).

Matches a project's Gemfile.lock against the ruby-advisory-db. A match is a
confirmed vulnerable gem (curated advisories = zero false positives). Also flags
insecure gem sources (http:// instead of https://). Completes the multi-language
SCA set alongside npm / cargo / go / pip / osv.

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> find Gemfile.lock)
  2. ScanRequest.target    (local dir with Gemfile.lock)
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
from tools._payloads.bundler_audit_scanner_findings import BUNDLER_AUDIT_SCANNER_FINDING_RULES

router = APIRouter()
BUNDLER_AUDIT_BIN = shutil.which("bundler-audit") or shutil.which("bundle-audit") or "/usr/local/bin/bundler-audit"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 180


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


def _find_gemfile_dir(root: str) -> str:
    """Directory of the first Gemfile.lock within `root` (depth <= 3)."""
    root = root.rstrip("/")
    base = root.count(os.sep)
    for dp, dn, fn in os.walk(root):
        if dp.count(os.sep) - base > 3:
            dn[:] = []
            continue
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "vendor", "tmp")]
        if "Gemfile.lock" in fn:
            return dp
    return ""


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("bundler-audit") or shutil.which("bundle-audit") or os.path.exists(BUNDLER_AUDIT_BIN)):
            ctx.state["bun_error"] = "bundler-audit binary not installed"
            ctx.source("bundler-audit missing")
            return

        cleanup = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="bundaudit_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["bun_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                root = cleanup
                mode = "repo_url"
                ctx.state["bun_input_value"] = repo_url
            elif target and os.path.isdir(target):
                root = target
                mode = "local_path"
                ctx.state["bun_input_value"] = target
            else:
                ctx.state["bun_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["bun_input_mode"] = mode
            gemdir = _find_gemfile_dir(root)
            if not gemdir:
                ctx.state["bun_no_gemfile"] = True
                ctx.source("no Gemfile.lock")
                return
            ctx.state["bun_gemfile"] = os.path.relpath(os.path.join(gemdir, "Gemfile.lock"), root)

            cmd = [BUNDLER_AUDIT_BIN, "check", "--format", "json"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, cwd=gemdir,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["bun_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["bun_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source("subprocess failed")
                return

            # Non-zero exit when vulns found; JSON still on stdout.
            if not stdout:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["bun_error"] = f"bundler-audit rc={proc.returncode}: {err_text}"
                ctx.source(f"bundler-audit rc={proc.returncode}")
                return
            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["bun_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            results = data.get("results") or [] if isinstance(data, dict) else []
            top, vuln_gems, insecure = [], set(), []
            for r in results:
                rtype = r.get("type")
                if rtype == "unpatched_gem":
                    gem = r.get("gem") or {}
                    adv = r.get("advisory") or {}
                    vuln_gems.add(gem.get("name"))
                    top.append({"id": adv.get("id") or "?",
                                "gem": f"{gem.get('name', '?')}@{gem.get('version', '?')}",
                                "title": (adv.get("title") or "")[:80]})
                elif rtype == "insecure_source":
                    insecure.append(r.get("source") or "?")

            ctx.state["bun_vuln_count"] = len(top)
            ctx.state["bun_vuln_gem_count"] = len(vuln_gems)
            ctx.state["bun_top_vulns"] = top[:10]
            ctx.state["bun_insecure_sources"] = insecure[:5]
            ctx.source(f"bundler-audit: {len(top)} vuln(s) across {len(vuln_gems)} gem(s), "
                       f"{len(insecure)} insecure source(s)")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "bun_input_mode"),
                ("Scan input", "bun_input_value"),
                ("Lockfile", "bun_gemfile"),
                ("Vulnerable gems", "bun_vuln_gem_count"),
                ("Advisories", "bun_vuln_count"),
                ("Top advisories", "bun_top_vulns"),
                ("Insecure sources", "bun_insecure_sources")]


@router.post("/api/supply_chain/bundler_audit_scanner")
async def supply_chain_bundler_audit_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="bundler_audit_scanner",
        gather_func=_make_gather(req),
        finding_rules=BUNDLER_AUDIT_SCANNER_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
