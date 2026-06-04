"""grype_sbom_scan - SBOM -> CVE scan via syft|grype pipeline (playbook §2 #15 / §1 #5).

Two-stage scan:
  1. syft <target> -o cyclonedx-json  =>  in-memory SBOM
  2. grype sbom:- --output json        =>  CVE matches against the SBOM

This gives Anchore's "best of both" - syft's deep package detection (npm,
pip, gem, cargo, maven, go-mod, apk, deb, rpm) plus grype's per-ecosystem
CVE matcher. Same severity bucketing as Trivy so comparisons across two
independent scanners are apples-to-apples.

Customer input (one of):
  - ScanRequest.image_ref  -> sbom from container image
  - ScanRequest.repo_url   -> sbom from git repo (shallow clone -> dir)
  - ScanRequest.target     -> path on disk (fallback)

If none of these are usable, returns an INFO finding with the required input.
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
from tools._payloads.grype_sbom_scan_findings import GRYPE_SBOM_SCAN_FINDING_RULES

router = APIRouter()
SYFT_BIN = shutil.which("syft") or "/usr/local/bin/syft"
GRYPE_BIN = shutil.which("grype") or "/usr/local/bin/grype"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240


async def _shallow_clone(repo_url: str, dest: str) -> tuple[bool, str]:
    """Clone repo_url to dest with depth=1. Returns (ok, err)."""
    if not os.path.exists(GIT_BIN) and not shutil.which("git"):
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


async def _run_syft(scan_target: str) -> tuple[bytes, bytes, int]:
    """Generate SBOM via syft -> CycloneDX JSON. Returns (stdout, stderr, rc)."""
    proc = await asyncio.create_subprocess_exec(
        SYFT_BIN, "scan", scan_target, "-o", "cyclonedx-json", "-q",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return b"", b"syft timeout", -1
    return stdout, stderr, proc.returncode or 0


async def _run_grype(sbom_bytes: bytes) -> tuple[bytes, bytes, int]:
    """Pipe SBOM into grype, get JSON CVE output. Returns (stdout, stderr, rc)."""
    proc = await asyncio.create_subprocess_exec(
        GRYPE_BIN, "sbom:-", "-o", "json", "-q",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=sbom_bytes),
                                                  timeout=TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return b"", b"grype timeout", -1
    return stdout, stderr, proc.returncode or 0


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        repo_url = (getattr(req, "repo_url", None) or "").strip()

        if not shutil.which("syft") and not os.path.exists(SYFT_BIN):
            ctx.state["grype_sbom_scan_error"] = "syft binary not installed"
            ctx.source("syft missing")
            return
        if not shutil.which("grype") and not os.path.exists(GRYPE_BIN):
            ctx.state["grype_sbom_scan_error"] = "grype binary not installed"
            ctx.source("grype missing")
            return

        scan_target = ""
        tmp_clone = ""
        cleanup_needed = False
        try:
            if image_ref:
                scan_target = image_ref
                ctx.state["grype_input_mode"] = "image_ref"
                ctx.state["grype_input_value"] = image_ref
            elif repo_url:
                tmp_clone = tempfile.mkdtemp(prefix="grype_repo_")
                ok, err = await _shallow_clone(repo_url, tmp_clone)
                if not ok:
                    ctx.state["grype_sbom_scan_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                cleanup_needed = True
                scan_target = f"dir:{tmp_clone}"
                ctx.state["grype_input_mode"] = "repo_url"
                ctx.state["grype_input_value"] = repo_url
            else:
                ctx.state["grype_sbom_scan_no_input"] = True
                ctx.source("image_ref or repo_url required")
                return

            # 1. syft -> SBOM
            sbom_bytes, syft_err, syft_rc = await _run_syft(scan_target)
            if syft_rc != 0 or not sbom_bytes:
                ctx.state["grype_sbom_scan_error"] = (
                    f"syft failed rc={syft_rc}: {syft_err.decode('utf-8', errors='ignore')[:160]}")
                ctx.source("syft failed")
                return

            # 2. SBOM -> grype
            grype_out, grype_err, grype_rc = await _run_grype(sbom_bytes)
            if grype_rc != 0 or not grype_out:
                ctx.state["grype_sbom_scan_error"] = (
                    f"grype failed rc={grype_rc}: {grype_err.decode('utf-8', errors='ignore')[:160]}")
                ctx.source("grype failed")
                return

            try:
                data = json.loads(grype_out.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["grype_sbom_scan_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            # Bucket by severity. grype "matches" list of {vulnerability, artifact, ...}.
            by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NEGLIGIBLE": 0, "UNKNOWN": 0}
            cves: list[dict] = []
            for m in (data.get("matches") or []):
                vuln = m.get("vulnerability") or {}
                art = m.get("artifact") or {}
                sev = (vuln.get("severity") or "UNKNOWN").upper()
                if sev in by_sev:
                    by_sev[sev] += 1
                fix = vuln.get("fix") or {}
                cves.append({
                    "id": vuln.get("id") or "?",
                    "severity": sev,
                    "pkg": art.get("name") or "?",
                    "installed": art.get("version") or "?",
                    "fixed": ", ".join(fix.get("versions") or []) if isinstance(fix.get("versions"), list) else "",
                    "ecosystem": art.get("type") or "",
                })
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                         "NEGLIGIBLE": 4, "UNKNOWN": 5}
            cves.sort(key=lambda c: (sev_order.get(c["severity"], 9), c["id"]))

            ctx.state["grype_severity_counts"] = by_sev
            ctx.state["grype_total_cves"] = sum(by_sev.values())
            ctx.state["grype_top_cves"] = cves[:10]
            ctx.state["grype_distro"] = (data.get("distro") or {})
            src = data.get("source") or {}
            ctx.state["grype_source_type"] = src.get("type") or ""
            ctx.source(f"grype: {sum(by_sev.values())} CVEs "
                       f"(C{by_sev['CRITICAL']}/H{by_sev['HIGH']}/M{by_sev['MEDIUM']})")
        finally:
            if cleanup_needed and tmp_clone:
                try:
                    shutil.rmtree(tmp_clone, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "grype_input_mode"),
                ("Scan input", "grype_input_value"),
                ("Source type", "grype_source_type"),
                ("Distro", "grype_distro"),
                ("CVE counts by severity", "grype_severity_counts"),
                ("Total CVEs", "grype_total_cves"),
                ("Top 10 CVEs", "grype_top_cves")]


@router.post("/api/supply_chain/grype_sbom_scan")
async def supply_chain_grype_sbom_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="grype_sbom_scan",
        gather_func=_make_gather(req),
        finding_rules=GRYPE_SBOM_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
