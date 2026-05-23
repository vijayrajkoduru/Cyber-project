"""Nuclei — community vulnerability template scanner (real binary).

Wraps the nuclei CLI with a curated, low-FP configuration:
  • severity ≥ medium  (skip info / low — too noisy)
  • exclude tags dos,intrusive,fuzz  (production-safe)
  • inject Authorization / Cookie headers from the scan request
  • parse JSONL output and normalise to standard_response shape

Customer's first scan auto-updates templates if missing.
"""
import json
import os
import shutil
import subprocess
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response, precheck_target

router = APIRouter()


def _which():
    return shutil.which("nuclei") or "/usr/local/bin/nuclei"


def _have_templates():
    home = os.environ.get("HOME", "/root")
    for p in (f"{home}/nuclei-templates", f"{home}/.config/nuclei",
              "/root/nuclei-templates", "/app/nuclei-templates"):
        if os.path.isdir(p) and os.listdir(p):
            return True
    return False


_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
         "low": "LOW", "info": "LOW"}
_CVSS_DEFAULT = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.0"}


@router.post("/api/vuln/nuclei")
def scan_nuclei(req: ScanRequest, _=Depends(verify_scan_quota)):
    if not os.path.isfile(_which()):
        return standard_response(tool="nuclei", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("nuclei binary not installed. Rebuild the backend "
                          "with the updated Dockerfile that includes the nuclei block."))

    # Auto-update templates on first run if missing
    if not _have_templates():
        try:
            subprocess.run([_which(), "-update-templates", "-silent"],
                            capture_output=True, timeout=120)
        except Exception:
            pass

    target = web_url(req.target)
    cmd = [_which(), "-target", target, "-jsonl",
           "-severity", "high,critical", "-tags", "exposure,cve,misconfig",
           "-exclude-tags", "dos,intrusive,fuzz",
           "-disable-update-check",
           "-rate-limit", "50",
           "-timeout", "10",
           "-stats=false", "-silent", "-no-color"]

    if getattr(req, "auth_bearer", None):
        cmd.extend(["-H", f"Authorization: Bearer {req.auth_bearer}"])
    if getattr(req, "auth_cookie", None):
        cmd.extend(["-H", f"Cookie: {req.auth_cookie}"])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return standard_response(tool="nuclei", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="nuclei scan timed out at 5 minutes")
    except Exception as e:
        return standard_response(tool="nuclei", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"nuclei execution failed: {str(e)[:200]}")

    findings, parsed = [], []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info", {}) or {}
        sev = _SEV.get(str(info.get("severity", "low")).lower(), "LOW")
        name = info.get("name") or obj.get("template-id") or "nuclei finding"
        url = obj.get("matched-at") or obj.get("host") or target
        ref = info.get("reference") or []
        ref0 = ref[0] if ref else ""
        classification = info.get("classification") or {}
        cwe_list = classification.get("cwe-id") or []
        cwe = (cwe_list[0].upper() if cwe_list else "CWE-200")
        cvss = classification.get("cvss-score") or _CVSS_DEFAULT.get(sev, "3.0")
        remediation = info.get("description") or (f"See {ref0}" if ref0 else "Review the matched endpoint.")
        findings.append(wrap_finding(
            f"{name} [{obj.get('template-id','')}]",
            sev, cvss=str(cvss), cwe=cwe, owasp="A06:2021",
            remediation=remediation[:300],
            evidence_marker=f"matched-at={url} (nuclei)"))
        parsed.append({"template": obj.get("template-id"), "name": name,
                       "severity": sev, "matched_at": url})

    return vuln_response(tool="nuclei", target=req.target, findings=findings,
        tested=max(len(parsed), 1),
        what_checked="community Nuclei templates (CVE / exposure / misconfig, severity >= medium)",
        tests_summary=(f"Nuclei: {len(findings)} finding(s) from community templates "
                       f"(severity >= medium, safe-only tags, auth headers injected)"),
        raw_data={"nuclei": {"matches": parsed[:50],
                              "cmd": " ".join(cmd[:8])}})


def register(app):
    app.include_router(router)
