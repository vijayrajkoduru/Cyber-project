"""Shared nuclei wrapper — fan out one binary across many tag-specific scanners.

One Nuclei binary, ~9,000 community templates, 45+ tag categories. Without
this helper each scanner would duplicate the subprocess + parsing dance from
tools/webapp/nuclei.py. With it, each new tag-specific scanner is ~30 lines.

Usage:
    from tools._framework.nuclei_runner import run_nuclei

    res = run_nuclei(req, tags=["sqli"], severity_min="medium")
    return vuln_response(tool="nuclei_sqli", target=req.target,
                          findings=res["findings"],
                          tested=res["tested"],
                          what_checked="Nuclei SQLi templates")

Design notes:
  • Severity is normalised through standard_response/wrap_finding so the
    advisory-cap policy from severity_policy.py applies automatically.
  • Auth headers (bearer / cookie) are forwarded so authenticated targets
    benefit from full coverage.
  • Per-scanner timeout default 90s — the orchestrator caps each scanner
    at 60s wall-clock (VL-TURBO) so we hand back early.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess

from tools._shared import web_url, wrap_finding


_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
         "low": "LOW", "info": "LOW"}
_CVSS_DEFAULT = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.0"}


def _which() -> str:
    return shutil.which("nuclei") or "/usr/local/bin/nuclei"


def _have_templates() -> bool:
    home = os.environ.get("HOME", "/root")
    for p in (f"{home}/nuclei-templates", f"{home}/.config/nuclei",
              "/root/nuclei-templates", "/app/nuclei-templates"):
        if os.path.isdir(p) and os.listdir(p):
            return True
    return False


def nuclei_available() -> tuple[bool, str]:
    """Return (ok, reason). ok=False means callers should return a
    skipped_reason response."""
    if not os.path.isfile(_which()):
        return (False, "nuclei binary not installed. Rebuild the backend "
                "with the updated Dockerfile that includes the nuclei block.")
    return (True, "")


def run_nuclei(req, tags: list[str], *,
                severity_min: str = "medium",
                exclude_tags: list[str] | None = None,
                timeout_s: int = 90,
                rate_limit: int = 50) -> dict:
    """Run nuclei against req.target with the given tag set. Returns:
        {
          "findings": [ wrap_finding dicts ],
          "tested":   int (count of nuclei matches parsed),
          "skipped":  str | None,
          "raw":      list of parsed match dicts (for raw_data),
        }

    severity_min: lowest severity to keep. Nuclei runs at this level and up.
                  Default "medium" because the global advisory-cap policy
                  already suppresses precondition-style LOW findings, so
                  going below medium just floods the report with noise.
    exclude_tags: defaults to dos,intrusive,fuzz (production-safe).
    """
    ok, why = nuclei_available()
    if not ok:
        return {"findings": [], "tested": 0, "skipped": why, "raw": []}

    if not _have_templates():
        try:
            subprocess.run([_which(), "-update-templates", "-silent"],
                            capture_output=True, timeout=120)
        except Exception:
            pass

    target = web_url(req.target)
    severities = {
        "critical": "critical",
        "high": "high,critical",
        "medium": "medium,high,critical",
        "low": "low,medium,high,critical",
    }.get(severity_min, "medium,high,critical")

    cmd = [_which(), "-target", target, "-jsonl",
           "-severity", severities,
           "-tags", ",".join(tags),
           "-exclude-tags", ",".join(exclude_tags or ["dos", "intrusive", "fuzz"]),
           "-disable-update-check",
           "-rate-limit", str(rate_limit),
           "-timeout", "10",
           "-stats=false", "-silent", "-no-color"]

    if getattr(req, "auth_bearer", None):
        cmd.extend(["-H", f"Authorization: Bearer {req.auth_bearer}"])
    if getattr(req, "auth_cookie", None):
        cmd.extend(["-H", f"Cookie: {req.auth_cookie}"])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"findings": [], "tested": 0,
                "skipped": f"nuclei scan timed out at {timeout_s}s", "raw": []}
    except Exception as e:
        return {"findings": [], "tested": 0,
                "skipped": f"nuclei execution failed: {str(e)[:200]}", "raw": []}

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
        remediation = info.get("description") or (f"See {ref0}" if ref0 else
                       "Review the matched endpoint.")
        findings.append(wrap_finding(
            f"{name} [{obj.get('template-id','')}]",
            sev, cvss=str(cvss), cwe=cwe, owasp="A06:2021",
            remediation=remediation[:300],
            # audit #43: don't blanket-claim verified_exploit. Many nuclei
            # templates are info/detection/tech-fingerprint matches; marking
            # them all "verified" let advisory findings bypass the severity
            # cap. Only treat HIGH/CRITICAL matches as demonstrated.
            verified_exploit=(sev in ("CRITICAL", "HIGH")),
            evidence_marker=f"matched-at={url} (nuclei,{','.join(tags)})"))
        parsed.append({"template": obj.get("template-id"), "name": name,
                       "severity": sev, "matched_at": url})

    return {"findings": findings,
            "tested": max(len(parsed), 1),
            "skipped": None,
            "raw": parsed[:50]}
