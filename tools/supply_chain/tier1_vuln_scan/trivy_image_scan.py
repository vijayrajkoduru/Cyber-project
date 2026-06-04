"""trivy_image_scan - Container image CVE scan via Trivy (playbook §2 #15 / §7 #85).

Wraps `trivy image --format json --quiet <image_ref>` against the customer-
provided ScanRequest.image_ref. Parses Trivy's JSON output (Results[].Vulnerabilities[])
and buckets findings by severity (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN). Returns
top-10 CVE IDs as evidence + a per-severity histogram.

Customer input:
  - ScanRequest.image_ref = OCI image ref (e.g. "nginx:1.21", "alpine:3.18")

If image_ref is absent the scanner returns an INFO finding explaining the
required input rather than guessing from the URL target. Trivy uses its
embedded vuln DB so no network call is needed at scan time (DB is refreshed
on container build).
"""
from __future__ import annotations
import asyncio
import json
import shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.trivy_image_scan_findings import TRIVY_IMAGE_SCAN_FINDING_RULES

router = APIRouter()
TRIVY_BIN = shutil.which("trivy") or "/usr/local/bin/trivy"
TIMEOUT = 180


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        if not image_ref:
            ctx.state["trivy_image_scan_no_input"] = True
            ctx.source("image_ref required")
            return
        if not shutil.which("trivy") and not __import__("os").path.exists(TRIVY_BIN):
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

        # Aggregate severity counts + collect CVE IDs.
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        cves: list[dict] = []
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
        # Sort: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN, then alpha.
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        cves.sort(key=lambda c: (sev_order.get(c["severity"], 9), c["id"]))

        ctx.state["trivy_severity_counts"] = by_sev
        ctx.state["trivy_total_cves"] = sum(by_sev.values())
        ctx.state["trivy_top_cves"] = cves[:10]
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
                ("Top 10 CVEs", "trivy_top_cves")]


@router.post("/api/supply_chain/trivy_image_scan")
async def supply_chain_trivy_image_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="trivy_image_scan",
        gather_func=_make_gather(req),
        finding_rules=TRIVY_IMAGE_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
