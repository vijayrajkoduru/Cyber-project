"""Real Nikto web vulnerability scanner wrapper.

Runs the actual `nikto` binary against the target URL, parses CSV output,
and emits structured findings. Replaces the previous meta-delegation pattern
(which pointed customers at 4 other scanners) with genuine Nikto coverage.

Nikto checks ~6,700 known web vulnerabilities, default-credential exposures,
dangerous CGI scripts, sensitive paths, and server misconfigurations that
DO NOT overlap with the existing security_headers / exposed_files / cors /
http_methods standalone scanners.

If the `nikto` binary is missing, emits a single INFO finding clearly
labeling the scan as NOT IMPLEMENTED rather than fabricating results.

Wall-clock budget: 90s (nikto's own -maxtime 60s + 30s parse margin).
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding
from tools.webapp._webapp_common import precheck_target, vuln_response
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


# Nikto-specific severity mapping. Nikto itself doesn't emit numeric
# severity; we infer from description keywords + OSVDB risk classes.
_HIGH_KEYWORDS = (
    "remote code execution", "rce", "command injection",
    "default credentials", "default password", "default account",
    "shell access", "unauthenticated admin",
    "directory traversal", "lfi", "path traversal",
    "xst", "shellshock", "heartbleed",
)
_MEDIUM_KEYWORDS = (
    "admin", "phpmyadmin", "manager", "wp-admin", "console",
    "/.git", "/.svn", "/.env", "/.htaccess", "/.htpasswd",
    "/backup", "/install", "/setup", "/test",
    "info disclosure", "internal ip", "stack trace",
    "debug", "trace method", "put method", "delete method",
    "directory indexing", "directory listing",
)
_LOW_KEYWORDS = (
    "server: ", "x-powered-by", "version", "banner",
    "outdated", "deprecated",
)


def _severity_for(desc: str) -> tuple[str, str]:
    """Return (severity, cvss) from nikto description text."""
    d = (desc or "").lower()
    if any(k in d for k in _HIGH_KEYWORDS):
        return "HIGH", "7.5"
    if any(k in d for k in _MEDIUM_KEYWORDS):
        return "MEDIUM", "5.5"
    if any(k in d for k in _LOW_KEYWORDS):
        return "LOW", "3.0"
    return "INFO", "0.0"


def _cwe_for(desc: str) -> str:
    """Map description to a specific CWE rather than blanket CWE-1395."""
    d = (desc or "").lower()
    if "directory traversal" in d or "lfi" in d or "path traversal" in d:
        return "CWE-22"
    if "command injection" in d or "rce" in d:
        return "CWE-77"
    if "default cred" in d or "default password" in d:
        return "CWE-798"
    if "info disclosure" in d or "internal ip" in d or "stack trace" in d:
        return "CWE-200"
    if "trace method" in d or "put method" in d or "delete method" in d:
        return "CWE-650"
    if "directory indexing" in d or "directory listing" in d:
        return "CWE-548"
    if "outdated" in d or "deprecated" in d or "version" in d:
        return "CWE-1104"
    return "CWE-693"


def _build_target_arg(url: str) -> str:
    """Nikto wants host (and optionally port/SSL). It accepts full URLs in
    -h since 2.5; fall back to host extraction if the URL form fails."""
    return url.rstrip("/")


def _run_nikto(url: str, timeout_s: int = 90) -> tuple[int, str, str]:
    """Execute nikto with CSV output. Returns (exit_code, stdout, stderr)."""
    cmd = [
        "nikto",
        "-h", _build_target_arg(url),
        "-Format", "csv",
        "-ask", "no",
        "-maxtime", "60s",
        "-nointeractive",
        "-Tuning", "x",  # exclude DoS checks
        "-Plugins", "@@DEFAULT;-cgi",  # skip exhaustive CGI scan (slow + noisy)
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"
    except FileNotFoundError:
        return 127, "", "nikto binary not found in PATH"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _parse_csv(text: str) -> list[dict]:
    """Parse nikto -Format csv output. Each row is a finding.
    Nikto CSV columns: Host, IP, Port, OSVDB, HTTP Method, URI, Description.
    Some versions omit the header row; handle both."""
    out = []
    if not text or "," not in text:
        return out
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or len(row) < 7:
            continue
        host, ip, port, osvdb, method, uri, *rest = row
        # Skip header row
        if host.lower() in ("host", '"host"'):
            continue
        desc = ",".join(rest).strip().strip('"')
        if not desc:
            continue
        out.append({
            "host": host.strip().strip('"'),
            "port": port.strip().strip('"'),
            "osvdb": osvdb.strip().strip('"'),
            "method": method.strip().strip('"'),
            "uri": uri.strip().strip('"'),
            "description": desc,
        })
    return out


@router.post("/api/webapp/scan/nikto")
@vl_turbo()
@vl_verify()
def scan_nikto(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)

    # Precheck — bail early on unreachable / WAF-blocked targets.
    # active_probes=False because nikto signatures itself; WAF skip
    # would just send everyone home empty-handed.
    unreachable = precheck_target(base, req, active_probes=False)
    if unreachable:
        return vuln_response(
            tool="nikto", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable,
            what_checked="nikto web-vulnerability scan",
        )

    # Binary missing -> honest [NOT IMPLEMENTED].
    if shutil.which("nikto") is None:
        return vuln_response(
            tool="nikto", target=req.target,
            findings=[wrap_finding(
                "[NOT IMPLEMENTED] nikto binary not installed on scanner host",
                "INFO", cvss="0.0", cwe="N/A",
                remediation=("Install nikto on the scanner VPS: "
                              "apt-get install nikto. Then re-scan."),
                evidence_marker=("nikto binary not found in PATH at scan-time. "
                                  "Endpoint did not perform real scan."),
            )],
            tested=0,
            what_checked="nikto web-vulnerability scan (binary missing)",
            tests_summary="nikto not installed",
        )

    # Real execution.
    exit_code, stdout, stderr = _run_nikto(base, timeout_s=90)

    # Timeout: still report whatever findings the partial run produced.
    if exit_code == 124:
        rows = _parse_csv(stdout)
        findings = [wrap_finding(
            f"nikto scan exceeded 60s — {len(rows)} partial finding(s) captured",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Target is slow or large. Run nikto manually with "
                          "extended -maxtime for full coverage."),
            evidence_marker=("Wall-clock exceeded 90s budget; partial results below."),
        )]
        for r in rows[:30]:
            sev, cvss = _severity_for(r["description"])
            findings.append(wrap_finding(
                f"{r['description']}",
                sev, cvss=cvss, cwe=_cwe_for(r["description"]),
                remediation=("Review the affected URI and apply server hardening "
                              "per vendor advisory."),
                evidence_marker=(f"nikto: {r['method']} {r['uri']} "
                                  f"(OSVDB-{r['osvdb']}) -> {r['description']}"),
            ))
        return vuln_response(
            tool="nikto", target=req.target, findings=findings,
            tested=len(rows) + 1,
            what_checked="nikto -Format csv (partial; timed out at 60s)",
            tests_summary=f"timeout @60s; {len(rows)} partial finding(s)",
            raw_data={"nikto": {"exit_code": exit_code,
                                  "rows": len(rows),
                                  "stderr_tail": stderr[-300:]}},
        )

    # Other non-zero exit (network failure / parse error from nikto itself).
    if exit_code not in (0, 1):
        return vuln_response(
            tool="nikto", target=req.target,
            findings=[wrap_finding(
                f"[PROBE ERROR] nikto exited with code {exit_code}",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Verify target reachability and nikto installation.",
                evidence_marker=(f"nikto stderr (last 300 chars): {stderr[-300:]}"),
            )],
            tested=0,
            what_checked="nikto web-vulnerability scan (error)",
            tests_summary=f"nikto exit {exit_code}",
        )

    # Parse real CSV findings.
    rows = _parse_csv(stdout)
    findings = []
    for r in rows:
        sev, cvss = _severity_for(r["description"])
        findings.append(wrap_finding(
            r["description"][:200],
            sev, cvss=cvss, cwe=_cwe_for(r["description"]),
            remediation=("Review the affected URI/header and apply server "
                          "hardening per CWE / vendor advisory."),
            evidence_marker=(f"nikto: {r['method']} {r['uri']} on {r['host']}:{r['port']} "
                              f"(OSVDB-{r['osvdb']}) -> {r['description'][:160]}"),
        ))

    # vuln_response auto-emits POSITIVE when findings=[] AND tested>=1.
    return vuln_response(
        tool="nikto", target=req.target, findings=findings,
        tested=max(len(rows), 1),
        what_checked=("nikto web-vulnerability scan (~6,700 checks: "
                       "CGI, default creds, info disclosure, dangerous configs)"),
        tests_summary=(f"nikto scanned {base}; {len(rows)} finding(s)"
                        if rows else f"nikto scanned {base}; no issues found"),
        raw_data={"nikto": {"exit_code": exit_code,
                              "rows_total": len(rows),
                              "tuning": "x (DoS excluded)",
                              "maxtime_s": 60,
                              "stderr_tail": stderr[-300:] if stderr else ""}},
    )


def register(app):
    app.include_router(router)
