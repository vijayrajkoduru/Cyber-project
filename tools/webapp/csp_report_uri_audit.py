"""csp_report_uri_audit — CSP report-uri / report-to disclosure + leak audit.

CSP report-uri directive sends violation reports to a URL. Misuse:
  - report-uri pointing to a third-party SaaS (Sentry, Datadog) — sends
    DOM + URL data including session tokens in query strings
  - report-uri pointing to attacker-controlled URL (typo / supply-chain)
  - Reports include sensitive page state (URL with auth tokens, etc.)
"""
import re
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

KNOWN_REPORT_PROVIDERS = [
    "sentry.io", "datadoghq.com", "newrelic.com",
    "report-uri.com", "uriports.com", "csper.io",
    "reportu.com",
]


@router.post("/api/webapp/scan/csp_report_uri_audit")
def scan_csp_report_uri_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="csp_report_uri_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from target")

    csp = (r.headers.get("content-security-policy") or
           r.headers.get("Content-Security-Policy") or "")
    csp_ro = (r.headers.get("content-security-policy-report-only") or
              r.headers.get("Content-Security-Policy-Report-Only") or "")
    rt_header = (r.headers.get("report-to") or r.headers.get("Report-To") or "")
    reporting_endpoints = (r.headers.get("reporting-endpoints") or
                            r.headers.get("Reporting-Endpoints") or "")

    # Extract report-uri values from CSP / CSP-RO
    report_uris = set()
    for header_value in (csp, csp_ro):
        for m in re.finditer(r"report-uri\s+([^;]+)", header_value, re.IGNORECASE):
            for url_part in m.group(1).split():
                report_uris.add(url_part.strip())

    # Extract report-to / reporting-endpoints
    report_groups = set()
    for header_value in (csp, csp_ro):
        for m in re.finditer(r"report-to\s+([^;]+)", header_value, re.IGNORECASE):
            for grp in m.group(1).split():
                report_groups.add(grp.strip())

    findings = []
    if not (csp or csp_ro):
        # No CSP at all — covered by csp3_audit; just note it
        return standard_response(
            tool="csp_report_uri_audit", target=req.target,
            findings=[wrap_finding(
                "No CSP headers — no report-uri to audit",
                "INFO", cwe="CWE-200",
                remediation="See csp3_audit scanner for full CSP guidance.",
                evidence_marker="no Content-Security-Policy or Report-Only header")],
            tests_performed=1, vulnerable=False,
            tests_summary="No CSP")

    target_host = urlparse(url).hostname or ""
    if not report_uris and not report_groups:
        findings.append(wrap_finding(
            "CSP set but no report-uri / report-to — no telemetry",
            "INFO", cwe="CWE-1295",
            remediation="Add report-uri (legacy) or Reporting-Endpoints + report-to "
                        "(modern) to collect CSP violation reports. Without telemetry "
                        "you won't know when CSP blocks something user-affecting "
                        "(broken third-party SDK, etc).",
            evidence_marker="CSP present, no reporting directives"))
    else:
        # Audit each report-uri
        external = []
        third_party_provider = []
        for uri in report_uris:
            # Strip quotes
            uri_clean = uri.strip("\"'")
            parsed_uri = urlparse(uri_clean) if uri_clean.startswith("http") else None
            if parsed_uri and parsed_uri.hostname:
                if parsed_uri.hostname != target_host:
                    external.append(uri_clean)
                    for p in KNOWN_REPORT_PROVIDERS:
                        if p in parsed_uri.hostname:
                            third_party_provider.append({"uri": uri_clean, "provider": p})
                            break

        if external:
            third_party_names = ", ".join({tp["provider"] for tp in third_party_provider})
            sev = "LOW" if third_party_provider else "MEDIUM"
            cvss = "3.5" if third_party_provider else "5.3"
            findings.append(wrap_finding(
                f"CSP report-uri sends data to external host(s) ({len(external)})",
                sev, cvss=cvss, cwe="CWE-1295", owasp="A05:2021",
                remediation=("Confirm each report-uri is intentional. Known providers "
                              f"({third_party_names}) are typically OK. Unknown external "
                              "URIs could be supply-chain / typo. CSP reports include URL "
                              "fragments + DOM snippets — make sure URLs never contain "
                              "auth tokens / PII in query strings (use bearer headers, not "
                              "?token=...)."),
                evidence_marker=" | ".join(external[:5])))
        if not external:
            findings.append(wrap_finding(
                f"CSP report-uri stays same-origin ({len(report_uris)} URI(s))",
                "POSITIVE", cwe="CWE-1295",
                remediation="Maintain. Self-hosted CSP report collector avoids "
                            "third-party data exposure.",
                evidence_marker=" | ".join(list(report_uris)[:5])))

    return standard_response(
        tool="csp_report_uri_audit", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"report-uri: {len(report_uris)}, report-to: {len(report_groups)}",
        raw_data={"report_uris": list(report_uris),
                   "report_groups": list(report_groups),
                   "report_to_header": rt_header[:200],
                   "reporting_endpoints_header": reporting_endpoints[:200]})


def register(app):
    app.include_router(router)
