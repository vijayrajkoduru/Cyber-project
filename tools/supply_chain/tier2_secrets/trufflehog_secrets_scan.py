"""trufflehog_secrets_scan - verified secret detection via TruffleHog (playbook §2).

Where gitleaks does regex/entropy detection, TruffleHog additionally **verifies**
a candidate secret against its provider (read-only auth check). A VERIFIED hit is
a confirmed, currently-live leaked credential — the highest-severity supply-chain
finding and effectively zero false positive. Unverified hits are reported lower.

Customer input precedence:
  1. ScanRequest.repo_url  (shallow clone -> scan the working tree)
  2. ScanRequest.target    (local dir)
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
from tools._payloads.trufflehog_secrets_scan_findings import TRUFFLEHOG_SECRETS_SCAN_FINDING_RULES

router = APIRouter()
TRUFFLEHOG_BIN = shutil.which("trufflehog") or "/usr/local/bin/trufflehog"
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


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not (shutil.which("trufflehog") or os.path.exists(TRUFFLEHOG_BIN)):
            ctx.state["th_error"] = "trufflehog binary not installed"
            ctx.source("trufflehog missing")
            return

        cleanup = ""
        try:
            if repo_url:
                cleanup = tempfile.mkdtemp(prefix="trufflehog_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup)
                if not ok:
                    ctx.state["th_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                root = cleanup
                mode = "repo_url"
                ctx.state["th_input_value"] = repo_url
            elif target and os.path.isdir(target):
                root = target
                mode = "local_path"
                ctx.state["th_input_value"] = target
            else:
                ctx.state["th_no_input"] = True
                ctx.source("repo_url or local path required")
                return

            ctx.state["th_input_mode"] = mode
            cmd = [TRUFFLEHOG_BIN, "filesystem", root, "--json", "--no-update"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["th_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["th_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source("subprocess failed")
                return

            # TruffleHog emits JSON-lines (one object per finding). No findings =
            # empty stdout + rc 0 (a clean repo), which is NOT an error.
            verified, unverified, detectors, samples = 0, 0, {}, []
            for line in (stdout or b"").decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line[0] != "{":
                    continue
                try:
                    f = json.loads(line)
                except Exception:
                    continue
                det = f.get("DetectorName") or "?"
                is_verified = bool(f.get("Verified"))
                if is_verified:
                    verified += 1
                else:
                    unverified += 1
                detectors[det] = detectors.get(det, 0) + 1
                if len(samples) < 12:
                    meta = (((f.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
                    samples.append({"detector": det, "verified": is_verified,
                                    "file": meta.get("file") or "?", "line": meta.get("line") or ""})

            ctx.state["th_verified"] = verified
            ctx.state["th_unverified"] = unverified
            ctx.state["th_detectors"] = sorted(detectors.keys())
            ctx.state["th_samples"] = samples
            ctx.state["th_ran"] = True
            ctx.source(f"trufflehog: {verified} verified / {unverified} unverified secret(s)")
        finally:
            if cleanup:
                try:
                    shutil.rmtree(cleanup, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "th_input_mode"),
                ("Scan input", "th_input_value"),
                ("Verified live secrets", "th_verified"),
                ("Unverified candidates", "th_unverified"),
                ("Detectors that fired", "th_detectors"),
                ("Samples", "th_samples")]


@router.post("/api/supply_chain/trufflehog_secrets_scan")
async def supply_chain_trufflehog_secrets_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="trufflehog_secrets_scan",
        gather_func=_make_gather(req),
        finding_rules=TRUFFLEHOG_SECRETS_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
