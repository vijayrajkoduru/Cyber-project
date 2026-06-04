"""syft_sbom_generate - SBOM generation via syft (playbook §1 #1).

Generates an SBOM in CycloneDX-JSON format from an image_ref or repo_url
and persists it to a tempfile so downstream consumers (Dependency-Track,
cosign attest, OpenVEX) can ingest it. Returns:
  - SBOM artifact path
  - total component count
  - per-package-type breakdown (npm, pip, maven, apk, deb, go-module, etc.)

INFO finding always (this scanner is producing an artifact, not detecting
vulnerabilities). For vuln matching see grype_sbom_scan / trivy_image_scan.

Customer input precedence:
  1. ScanRequest.image_ref
  2. ScanRequest.repo_url   (shallow clone -> syft dir)
  3. ScanRequest.target     (if it's a usable local path)

Mandated by EU CRA (2024+) + US EO 14028 - every shipped artifact must
have a transferable SBOM.
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
from tools._payloads.syft_sbom_generate_findings import SYFT_SBOM_GENERATE_FINDING_RULES

router = APIRouter()
SYFT_BIN = shutil.which("syft") or "/usr/local/bin/syft"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240

# SBOM artifacts persist for downstream consumption (cosign attest, DT push).
_SBOM_OUT_DIR = os.environ.get("VL_SBOM_OUT_DIR", "/tmp/vl_sboms")


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
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not shutil.which("syft") and not os.path.exists(SYFT_BIN):
            ctx.state["syft_sbom_generate_error"] = "syft binary not installed"
            ctx.source("syft missing")
            return

        scan_source = ""
        cleanup_path = ""
        mode = ""
        try:
            if image_ref:
                scan_source = image_ref
                mode = "image_ref"
                ctx.state["syft_input_value"] = image_ref
            elif repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="syft_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["syft_sbom_generate_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_source = f"dir:{cleanup_path}"
                mode = "repo_url"
                ctx.state["syft_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_source = f"dir:{target}"
                mode = "local_path"
                ctx.state["syft_input_value"] = target
            else:
                ctx.state["syft_sbom_generate_no_input"] = True
                ctx.source("image_ref or repo_url required")
                return

            ctx.state["syft_input_mode"] = mode
            try:
                os.makedirs(_SBOM_OUT_DIR, exist_ok=True)
                sbom_path = tempfile.mktemp(prefix="sbom_", suffix=".cdx.json", dir=_SBOM_OUT_DIR)
            except Exception:
                # Fallback to /tmp if our directory isn't writeable.
                sbom_path = tempfile.mktemp(prefix="sbom_", suffix=".cdx.json")

            cmd = [SYFT_BIN, "scan", scan_source,
                   "-o", f"cyclonedx-json={sbom_path}", "-q"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["syft_sbom_generate_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["syft_sbom_generate_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source(f"subprocess failed: {str(e)[:80]}")
                return

            if proc.returncode != 0:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["syft_sbom_generate_error"] = f"syft rc={proc.returncode}: {err_text}"
                ctx.source(f"syft rc={proc.returncode}")
                return

            if not os.path.exists(sbom_path):
                ctx.state["syft_sbom_generate_error"] = "syft did not write SBOM file"
                ctx.source("no sbom file")
                return

            try:
                with open(sbom_path, "r", encoding="utf-8", errors="ignore") as fh:
                    sbom = json.load(fh)
            except Exception as e:
                ctx.state["syft_sbom_generate_error"] = f"sbom parse: {str(e)[:120]}"
                ctx.source("bad sbom json")
                return

            components = sbom.get("components") or []
            by_type: dict[str, int] = {}
            for c in components:
                # CycloneDX: 'type' is 'library' / 'application'. The package
                # ecosystem lives in 'purl' (pkg:npm/foo@1.0 etc).
                purl = c.get("purl") or ""
                eco = ""
                if purl.startswith("pkg:"):
                    eco = purl.split(":", 1)[1].split("/", 1)[0]
                if not eco:
                    eco = c.get("type") or "unknown"
                by_type[eco] = by_type.get(eco, 0) + 1

            ctx.state["sbom_artifact_path"] = sbom_path
            ctx.state["sbom_artifact_bytes"] = os.path.getsize(sbom_path)
            ctx.state["sbom_format"] = "CycloneDX-JSON"
            ctx.state["sbom_spec_version"] = sbom.get("specVersion") or "?"
            ctx.state["sbom_component_count"] = len(components)
            ctx.state["sbom_component_types"] = dict(
                sorted(by_type.items(), key=lambda x: -x[1])[:20]
            )
            # Stash the full SBOM for downstream consumers in this run.
            ctx.state["sbom_inline"] = {
                "format": "CycloneDX-JSON",
                "specVersion": sbom.get("specVersion"),
                "component_count": len(components),
                "path": sbom_path,
            }
            ctx.source(f"syft: {len(components)} components across "
                       f"{len(by_type)} ecosystem(s)")
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "syft_input_mode"),
                ("Scan input", "syft_input_value"),
                ("SBOM artifact path", "sbom_artifact_path"),
                ("SBOM size (bytes)", "sbom_artifact_bytes"),
                ("SBOM format", "sbom_format"),
                ("CycloneDX spec version", "sbom_spec_version"),
                ("Total components", "sbom_component_count"),
                ("Components by ecosystem", "sbom_component_types")]


@router.post("/api/supply_chain/syft_sbom_generate")
async def supply_chain_syft_sbom_generate(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="syft_sbom_generate",
        gather_func=_make_gather(req),
        finding_rules=SYFT_SBOM_GENERATE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
