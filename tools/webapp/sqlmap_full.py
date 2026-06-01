"""Real sqlmap binary wrapper for the Webapp module.

Companion to the hand-rolled sqli.py (time-based blind only). sqlmap
covers broader attack surface: error-based, boolean-based, UNION-based,
out-of-band, stacked queries, second-order injection.

Strategy for SaaS safety:
- single URL, single batch run (no interactive prompts)
- level=2, risk=2 (default sqlmap "sweet spot" - meaningful coverage,
  bounded request volume)
- 90-second wall-clock cap per scan
- --threads=4 for parallel payload testing
- --batch + --no-cast --random-agent for non-interactive operation
- Crawl depth=1 (just the entry URL + its <form> targets)
- Output parsed from sqlmap's findings summary lines
"""
from __future__ import annotations

import re
import shutil
import subprocess
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding
from tools.webapp._webapp_common import precheck_target, vuln_response

router = APIRouter()


_TIMEOUT_S = 90


def _run_sqlmap(url: str) -> tuple[int, str, str]:
    """Execute sqlmap with conservative settings. Returns (exit, stdout, stderr)."""
    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",                  # no interactive prompts
        "--random-agent",           # vary User-Agent per request
        "--level=2",                # 2 = include cookies + URL params + POST params
        "--risk=2",                 # 2 = include heavy time-based + UNION
        "--threads=4",              # parallel payload testing
        "--timeout=10",             # per-request HTTP timeout
        "--retries=1",              # don't retry forever on transient failures
        "--no-cast",                # skip type casting (faster, no DBA needed)
        "--smart",                  # only test parameters that look promising
        "--crawl=1",                # crawl depth 1 (entry + same-form targets)
        "--disable-coloring",
        "--output-dir=/tmp/sqlmap", # don't pollute home dir
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_TIMEOUT_S, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), \
               (e.stderr or "").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
    except FileNotFoundError:
        return 127, "", "sqlmap binary not found in PATH"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _parse_findings(stdout: str) -> list[dict]:
    """Extract per-parameter SQLi findings from sqlmap stdout.

    sqlmap prints findings as ASCII tables like:
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1 AND 4537=4537
    """
    findings = []
    cur = None
    for line in (stdout or "").splitlines():
        line = line.rstrip()
        m_param = re.match(r"\s*Parameter:\s+(\S+)\s+\((GET|POST|COOKIE|HEADER)\)", line)
        if m_param:
            cur = {"param": m_param.group(1), "method": m_param.group(2),
                    "types": [], "titles": [], "payloads": []}
            findings.append(cur)
            continue
        if cur is None:
            continue
        m_type = re.match(r"\s*Type:\s+(.+)$", line)
        if m_type:
            cur["types"].append(m_type.group(1).strip())
        m_title = re.match(r"\s*Title:\s+(.+)$", line)
        if m_title:
            cur["titles"].append(m_title.group(1).strip())
        m_payload = re.match(r"\s*Payload:\s+(.+)$", line)
        if m_payload:
            cur["payloads"].append(m_payload.group(1).strip())

    # Also try to extract DB fingerprint (back-end DBMS) for evidence
    return findings


def _detect_dbms(stdout: str) -> str:
    """Try to extract sqlmap's detected DBMS, e.g. MySQL >= 5.0.0."""
    m = re.search(r"back-end DBMS:\s+(.+)$", stdout or "", re.MULTILINE)
    return m.group(1).strip() if m else ""


@router.post("/api/webapp/scan/sqlmap_full")
def scan_sqlmap_full(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)

    unreachable = precheck_target(base, req, active_probes=True)
    if unreachable:
        return vuln_response(
            tool="sqlmap_full", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable,
            what_checked="sqlmap full SQLi battery (boolean/error/UNION/time/stacked)",
        )

    # URL must have query params or be an obvious form-target endpoint.
    parsed = urlparse(base)
    if not parsed.query and not parsed.path.rstrip("/"):
        return vuln_response(
            tool="sqlmap_full", target=req.target, findings=[],
            tested=1, skipped_reason=("URL has no query parameters or path "
                                       "segments; sqlmap needs an injection "
                                       "surface. Provide a URL with ?id=... "
                                       "or POST endpoint."),
            what_checked="sqlmap full SQLi battery (skipped - no inject surface)",
        )

    if shutil.which("sqlmap") is None:
        return vuln_response(
            tool="sqlmap_full", target=req.target,
            findings=[wrap_finding(
                "[NOT IMPLEMENTED] sqlmap binary not installed on scanner host",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Install sqlmap on backend: apt-get install sqlmap.",
                evidence_marker="sqlmap not in PATH at scan-time",
            )],
            tested=0,
            what_checked="sqlmap full SQLi battery (binary missing)",
            tests_summary="sqlmap not installed",
        )

    exit_code, stdout, stderr = _run_sqlmap(base)

    # Timeout - report what we got
    if exit_code == 124:
        partial = _parse_findings(stdout)
        if partial:
            findings = [_render_finding(p, base, partial=True) for p in partial]
            findings.append(wrap_finding(
                "sqlmap scan exceeded 90s budget - partial results above",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Run sqlmap manually with longer timeout for full coverage.",
                evidence_marker=f"sqlmap stdout length: {len(stdout)}",
            ))
            return vuln_response(
                tool="sqlmap_full", target=req.target, findings=findings,
                tested=len(partial) + 1,
                what_checked="sqlmap full SQLi battery (timeout @90s)",
                tests_summary=f"timeout; {len(partial)} partial finding(s)",
                raw_data={"sqlmap": {"timeout": True,
                                       "stderr_tail": stderr[-300:]}},
            )
        return vuln_response(
            tool="sqlmap_full", target=req.target,
            findings=[wrap_finding(
                "sqlmap scan timeout @90s with no confirmed findings",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Target may be slow; run sqlmap manually.",
                evidence_marker=f"stderr: {stderr[-200:]}",
            )],
            tested=0,
            what_checked="sqlmap full SQLi battery (timeout)",
            tests_summary="timeout @90s",
        )

    # Real findings parsing
    findings_raw = _parse_findings(stdout)
    dbms = _detect_dbms(stdout)

    if findings_raw:
        findings = [_render_finding(p, base, dbms=dbms) for p in findings_raw]
        return vuln_response(
            tool="sqlmap_full", target=req.target, findings=findings,
            tested=len(findings_raw),
            what_checked=(f"sqlmap full SQLi battery (boolean/error/UNION/"
                           f"time/stacked) on {len(findings_raw)} parameter(s)"),
            tests_summary=(f"sqlmap: {len(findings_raw)} vulnerable param(s)"
                            + (f"; DBMS: {dbms}" if dbms else "")),
            raw_data={"sqlmap": {"exit_code": exit_code,
                                   "params_vulnerable": len(findings_raw),
                                   "dbms": dbms,
                                   "stderr_tail": stderr[-300:] if stderr else ""}},
        )

    # Clean scan - sqlmap finished, no SQLi confirmed
    return vuln_response(
        tool="sqlmap_full", target=req.target, findings=[],
        tested=1,
        what_checked="sqlmap full SQLi battery (boolean/error/UNION/time/stacked)",
        tests_summary=f"sqlmap completed; 0 SQLi confirmed on {base}",
        raw_data={"sqlmap": {"exit_code": exit_code, "params_vulnerable": 0,
                               "stderr_tail": stderr[-300:] if stderr else ""}},
    )


def _render_finding(p: dict, base: str, dbms: str = "", partial: bool = False) -> dict:
    """Convert one parameter's sqlmap output into a wrap_finding dict."""
    param = p.get("param", "?")
    method = p.get("method", "?")
    types = p.get("types") or []
    titles = p.get("titles") or []
    payloads = p.get("payloads") or []

    type_summary = ", ".join(sorted(set(types))) or "unknown"
    title_short = titles[0] if titles else "SQL Injection"
    payload_short = payloads[0][:140] if payloads else ""

    # All confirmed sqlmap findings are CRITICAL or HIGH depending on type.
    # error-based / UNION / stacked = RCE-grade -> CRITICAL
    # boolean / time-based blind = data-exfil -> HIGH
    sev = "CRITICAL" if any(
        t.lower().startswith(("error", "union", "stacked")) for t in types
    ) else "HIGH"
    cvss = "9.8" if sev == "CRITICAL" else "8.6"

    suffix = " (partial - scan timed out)" if partial else ""
    db_suffix = f" [{dbms}]" if dbms else ""

    return wrap_finding(
        f"SQLi confirmed in {method} parameter '{param}': {type_summary}{db_suffix}{suffix}",
        sev, cvss=cvss, cwe="CWE-89", owasp="A03:2021",
        remediation=(f"Parameterise all SQL queries using prepared statements. "
                      f"Validate + reject types/lengths server-side. Apply "
                      f"least-privilege DB user. Add WAF SQLi rule as defense "
                      f"in depth."),
        evidence_marker=(f"sqlmap: {title_short}; payload: {payload_short}; "
                          f"method={method}; param={param}"),
    )


def register(app):
    app.include_router(router)
