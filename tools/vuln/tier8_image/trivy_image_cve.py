"""trivy_image_cve - Container-image CVE scan via Trivy for the Vuln module.

Wires the Vuln scan-setup modal's IMAGE REFERENCE input, which previously was a
no-op (the Vuln module had no image scanner, so a supplied image was resolved
and displayed but never actually scanned -> 0 findings on image-rich targets
like JuiceShop). Runs `trivy image --format json <image_ref>` against
ScanRequest.image_ref and buckets CVEs by severity, reusing the shared
TRIVY_IMAGE_SCAN_FINDING_RULES so findings render identically to the
Supply-Chain trivy probe.

When no image_ref is supplied this returns an INFO finding explaining the
required input (never guesses from the URL target). Trivy uses its embedded
vuln DB (refreshed on container build) so no network DB call is made at scan
time - only the image pull.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import run_scanner
from tools._payloads.trivy_image_scan_findings import TRIVY_IMAGE_SCAN_FINDING_RULES
from tools._payloads.vuln._loader import load_json

router = APIRouter()
TRIVY_BIN = shutil.which("trivy") or "/usr/local/bin/trivy"
TIMEOUT = 180

# Offline CISA-KEV reference, keyed by EXACT CVE-ID. ENRICHMENT ONLY: we add a
# 'this Trivy-confirmed CVE is on CISA KEV' note to CVEs Trivy ALREADY reported,
# matched by exact CVE-ID dictionary lookup. This never creates a finding and
# never changes Trivy's severity grading - it only annotates the intel display.
# Inline {} fallback keeps the scanner working if the bundled JSON is absent.
_KEV_REF = load_json("kev_crossref", {})


def _make_gather(req: ScanRequest):
    async def gather(ctx):
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        if not image_ref:
            ctx.state["trivy_image_scan_no_input"] = True
            ctx.source("image_ref required - supply an OCI image in the scan setup")
            return
        if not shutil.which("trivy") and not os.path.exists(TRIVY_BIN):
            ctx.state["trivy_image_scan_error"] = "trivy binary not installed"
            ctx.source("trivy missing")
            return

        ctx.state["trivy_image_ref"] = image_ref
        cmd = [TRIVY_BIN, "image", "--format", "json", "--quiet",
               "--no-progress", "--timeout", f"{TIMEOUT}s", image_ref]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                ctx.state["trivy_image_scan_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except Exception as e:
            ctx.state["trivy_image_scan_error"] = f"subprocess: {str(e)[:120]}"
            ctx.source(f"subprocess failed: {str(e)[:80]}")
            return

        if not stdout:
            err = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            ctx.state["trivy_image_scan_error"] = f"trivy returned no output: {err}"
            ctx.source("empty output")
            return

        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            ctx.state["trivy_image_scan_error"] = f"json parse: {str(e)[:120]}"
            ctx.source("bad json")
            return

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        cves: list = []
        for result in (data.get("Results") or []):
            target_name = result.get("Target") or ""
            for v in (result.get("Vulnerabilities") or []):
                sev = (v.get("Severity") or "UNKNOWN").upper()
                if sev in by_sev:
                    by_sev[sev] += 1
                cves.append({
                    "id": v.get("VulnerabilityID") or "?",
                    "severity": sev,
                    "pkg": v.get("PkgName") or "?",
                    "installed": v.get("InstalledVersion") or "?",
                    "fixed": v.get("FixedVersion") or "",
                    "target": target_name,
                })
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        cves.sort(key=lambda c: (sev_order.get(c["severity"], 9), c["id"]))

        # CISA-KEV annotation (advisory, exact CVE-ID match only). For each CVE
        # Trivy already confirmed, look it up by its exact id; if present on the
        # reference KEV list, attach kev=True + ransomware context. No severity
        # change, no new finding - this only enriches the intel rows below.
        kev_hits = []
        for c in cves:
            ref = _KEV_REF.get(c["id"]) if isinstance(_KEV_REF, dict) else None
            if ref:
                c["kev"] = True
                c["kev_ransomware"] = bool(ref.get("known_ransomware"))
                c["kev_due_date"] = ref.get("due_date", "")
                kev_hits.append({"id": c["id"], "product": ref.get("product", ""),
                                 "ransomware": bool(ref.get("known_ransomware")),
                                 "due_date": ref.get("due_date", "")})

        ctx.state["trivy_severity_counts"] = by_sev
        ctx.state["trivy_total_cves"] = sum(by_sev.values())
        ctx.state["trivy_top_cves"] = cves[:10]
        # Advisory KEV note only - surfaced as an intel field, never as a finding.
        ctx.state["trivy_kev_cves"] = kev_hits
        ctx.state["trivy_artifact_type"] = data.get("ArtifactType") or "container_image"
        ctx.state["trivy_os"] = (data.get("Metadata", {}).get("OS") or {})
        ctx.source(f"trivy: {sum(by_sev.values())} CVEs "
                   f"(C{by_sev['CRITICAL']}/H{by_sev['HIGH']}/M{by_sev['MEDIUM']})")
    return gather


INTEL_FIELDS = [("Image scanned", "trivy_image_ref"),
                ("Artifact type", "trivy_artifact_type"),
                ("OS metadata", "trivy_os"),
                ("CVE counts by severity", "trivy_severity_counts"),
                ("Total CVEs", "trivy_total_cves"),
                ("Top 10 CVEs", "trivy_top_cves"),
                ("On CISA KEV (exact CVE-ID match)", "trivy_kev_cves")]


@router.post("/api/vuln/trivy_image_cve")
async def vuln_trivy_image_cve(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="trivy_image_cve",
        gather_func=_make_gather(req),
        finding_rules=TRIVY_IMAGE_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
