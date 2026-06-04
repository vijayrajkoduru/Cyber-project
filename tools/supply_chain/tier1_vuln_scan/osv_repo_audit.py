"""osv_repo_audit - OSV.dev vulnerability scan via osv-scanner (playbook §2 #15).

Wraps Google's osv-scanner which queries OSV.dev for vulns matching declared
dependencies. Unlike grype/trivy (which match against CVE DB by package
version), osv-scanner reads project manifests directly (package-lock.json,
requirements.txt, go.sum, Cargo.lock, Gemfile.lock, pom.xml, etc.) so the
ecosystem coverage is broader.

Customer input precedence:
  1. ScanRequest.image_ref -> `osv-scanner --format json --image <ref>`
  2. ScanRequest.repo_url  -> shallow clone, then `osv-scanner -r <dir>`
  3. ScanRequest.target    -> if it looks like an existing local path, recursive scan

Returns per-ecosystem vuln count + top vulnerability IDs as evidence.
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
from tools._payloads.osv_repo_audit_findings import OSV_REPO_AUDIT_FINDING_RULES

router = APIRouter()
OSV_BIN = shutil.which("osv-scanner") or "/usr/local/bin/osv-scanner"
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


async def _run_osv(args: list) -> tuple[bytes, bytes, int]:
    proc = await asyncio.create_subprocess_exec(
        OSV_BIN, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return b"", b"osv-scanner timeout", -1
    # osv-scanner returns rc=1 when vulns are found; that's not a failure.
    rc = proc.returncode or 0
    return stdout, stderr, rc


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not shutil.which("osv-scanner") and not os.path.exists(OSV_BIN):
            ctx.state["osv_repo_audit_error"] = "osv-scanner binary not installed"
            ctx.source("osv-scanner missing")
            return

        args = []
        cleanup_path = ""
        mode = ""
        try:
            if image_ref:
                # osv-scanner supports container image scans on Linux.
                args = ["scan", "image", "--format", "json", image_ref]
                mode = "image_ref"
                ctx.state["osv_input_value"] = image_ref
            elif repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="osv_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["osv_repo_audit_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                args = ["scan", "source", "--format", "json", "-r", cleanup_path]
                mode = "repo_url"
                ctx.state["osv_input_value"] = repo_url
            elif target and os.path.isdir(target):
                args = ["scan", "source", "--format", "json", "-r", target]
                mode = "local_path"
                ctx.state["osv_input_value"] = target
            else:
                ctx.state["osv_repo_audit_no_input"] = True
                ctx.source("image_ref or repo_url required")
                return

            ctx.state["osv_input_mode"] = mode
            stdout, stderr, rc = await _run_osv(args)
            # rc=1 means vulns found; rc>=2 is a real failure.
            if rc not in (0, 1) or not stdout:
                err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                # Fallback: try the legacy invocation if `scan` subcommand isn't supported.
                if "unknown command" in err.lower() or "expected" in err.lower():
                    legacy_args = ["--format", "json"]
                    if mode == "image_ref":
                        legacy_args += ["--image", image_ref]
                    else:
                        legacy_args += ["-r", cleanup_path or target]
                    stdout, stderr, rc = await _run_osv(legacy_args)
                if rc not in (0, 1) or not stdout:
                    ctx.state["osv_repo_audit_error"] = f"osv-scanner rc={rc}: {err}"
                    ctx.source(f"osv failed rc={rc}")
                    return

            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["osv_repo_audit_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            # osv-scanner JSON shape: { "results": [ { "source": {"path":...,"type":...},
            #                                          "packages":[ {"package":{"name","ecosystem"},
            #                                                        "vulnerabilities":[{"id","summary","severity":[{"type","score"}]}],
            #                                                        "groups":[...]}]}], ... }
            by_ecosystem: dict[str, int] = {}
            by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            vulns: list[dict] = []
            sources_scanned: list[dict] = []
            for r in (data.get("results") or []):
                src = r.get("source") or {}
                sources_scanned.append({"path": src.get("path") or "?",
                                          "type": src.get("type") or "?"})
                for p in (r.get("packages") or []):
                    pkg_info = p.get("package") or {}
                    eco = pkg_info.get("ecosystem") or "unknown"
                    for v in (p.get("vulnerabilities") or []):
                        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
                        # Severity is often nested in 'severity':[{"type":"CVSS_V3","score":"7.5"}]
                        # or 'database_specific.severity':"HIGH".
                        sev = "UNKNOWN"
                        for sev_entry in (v.get("severity") or []):
                            score_str = sev_entry.get("score") or ""
                            try:
                                if "/" in score_str:
                                    # CVSS vector string -> need separate calc; trust DB severity
                                    pass
                                else:
                                    score = float(score_str)
                                    if score >= 9.0: sev = "CRITICAL"
                                    elif score >= 7.0: sev = "HIGH"
                                    elif score >= 4.0: sev = "MEDIUM"
                                    else: sev = "LOW"
                            except Exception:
                                pass
                        dbsev = ((v.get("database_specific") or {}).get("severity") or "").upper()
                        if dbsev in by_sev:
                            sev = dbsev
                        if sev in by_sev:
                            by_sev[sev] += 1
                        vulns.append({
                            "id": v.get("id") or "?",
                            "summary": (v.get("summary") or "")[:120],
                            "pkg": pkg_info.get("name") or "?",
                            "ecosystem": eco,
                            "severity": sev,
                        })
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            vulns.sort(key=lambda v: (sev_order.get(v["severity"], 9), v["id"]))

            ctx.state["osv_total_vulns"] = sum(by_sev.values())
            ctx.state["osv_severity_counts"] = by_sev
            ctx.state["osv_by_ecosystem"] = by_ecosystem
            ctx.state["osv_top_vulns"] = vulns[:10]
            ctx.state["osv_sources_scanned"] = sources_scanned[:25]
            ctx.source(f"osv-scanner: {sum(by_sev.values())} vulns across "
                       f"{len(by_ecosystem)} ecosystem(s)")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "osv_input_mode"),
                ("Scan input", "osv_input_value"),
                ("Sources scanned", "osv_sources_scanned"),
                ("Vulns by ecosystem", "osv_by_ecosystem"),
                ("Severity counts", "osv_severity_counts"),
                ("Total vulns", "osv_total_vulns"),
                ("Top 10 vulnerabilities", "osv_top_vulns")]


@router.post("/api/supply_chain/osv_repo_audit")
async def supply_chain_osv_repo_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="osv_repo_audit",
        gather_func=_make_gather(req),
        finding_rules=OSV_REPO_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
