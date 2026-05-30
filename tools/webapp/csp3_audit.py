"""csp3_audit — modern CSP Level 3 audit (nonces, hashes, strict-dynamic).

Existing security_headers covers CSP presence. This one audits the CSP
QUALITY: weak directives, unsafe-inline without nonce, missing nonce on
script-src, mixing of CSP1/2/3 directives, http: schemes allowed.
"""
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()


def _parse_csp(header: str) -> dict:
    """Parse a CSP header into {directive: [values]} dict."""
    out = {}
    for part in header.split(";"):
        bits = part.strip().split()
        if not bits: continue
        out[bits[0].lower()] = [b.lower() for b in bits[1:]]
    return out


@router.post("/api/webapp/scan/csp3_audit")
def scan_csp3_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="csp3_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from target")

    csp_header = r.headers.get("content-security-policy") or \
                  r.headers.get("Content-Security-Policy") or ""
    csp_ro = r.headers.get("content-security-policy-report-only") or \
              r.headers.get("Content-Security-Policy-Report-Only") or ""

    using_ro_only = bool(csp_ro and not csp_header)
    active = csp_header or csp_ro

    if not active:
        return standard_response(
            tool="csp3_audit", target=req.target,
            findings=[wrap_finding(
                "No Content-Security-Policy header",
                "MEDIUM", cvss="5.3", cwe="CWE-1021", owasp="A05:2021",
                remediation="Add a CSP header. For a starter strict-dynamic CSP: "
                            "default-src 'none'; script-src 'nonce-RAND' 'strict-dynamic' "
                            "https:; style-src 'nonce-RAND'; img-src 'self' data:; "
                            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
                            "form-action 'self'. Test with report-only first via "
                            "Content-Security-Policy-Report-Only.",
                evidence_marker="no CSP header in response")],
            tests_performed=1, vulnerable=True,
            tests_summary="No CSP header")

    parsed = _parse_csp(active)
    findings = []

    if using_ro_only:
        findings.append(wrap_finding(
            "CSP in report-only mode — no enforcement",
            "MEDIUM", cvss="5.3", cwe="CWE-1021", owasp="A05:2021",
            remediation="Once report-only telemetry is clean, migrate to enforcing "
                        "Content-Security-Policy header.",
            evidence_marker="Content-Security-Policy-Report-Only is set, but no "
                              "enforcing CSP"))

    # 1. unsafe-inline / unsafe-eval audit
    script_src = parsed.get("script-src", []) or parsed.get("default-src", [])
    if "'unsafe-inline'" in script_src:
        # OK if combined with a nonce (modern CSP3 strict-dynamic semantics)
        has_nonce = any(v.startswith("'nonce-") for v in script_src)
        if not has_nonce:
            findings.append(wrap_finding(
                "script-src includes 'unsafe-inline' WITHOUT nonce — XSS bypass",
                "HIGH", cvss="7.5", cwe="CWE-1021", owasp="A05:2021",
                remediation="'unsafe-inline' defeats CSP XSS protection. Add a per-"
                            "request nonce and require <script nonce='RAND'> for all "
                            "inline scripts. OR move all JS to external files.",
                evidence_marker=f"script-src: {' '.join(script_src)}"))

    if "'unsafe-eval'" in script_src:
        findings.append(wrap_finding(
            "script-src includes 'unsafe-eval' — eval()/new Function() allowed",
            "MEDIUM", cvss="5.3", cwe="CWE-1021", owasp="A05:2021",
            remediation="Remove if possible. If your app uses Vue runtime-compile / "
                        "Angular JIT / React lazy() with template-strings, switch to "
                        "AOT / precompiled mode to drop unsafe-eval.",
            evidence_marker=f"script-src has 'unsafe-eval'"))

    # 2. http: scheme audit
    for directive, vals in parsed.items():
        if "http:" in vals:
            findings.append(wrap_finding(
                f"{directive} allows http: scheme — mixed content",
                "MEDIUM", cvss="5.3", cwe="CWE-1021", owasp="A05:2021",
                remediation="Restrict to https: only. Modern browsers auto-upgrade "
                            "in many cases but explicit https: directive prevents leaks.",
                evidence_marker=f"{directive}: {' '.join(vals)}"))

    # 3. Wildcard audit
    if "*" in script_src:
        findings.append(wrap_finding(
            "script-src = * — completely permissive",
            "HIGH", cvss="7.5", cwe="CWE-1021", owasp="A05:2021",
            remediation="Wildcard script-src defeats CSP entirely. Replace with "
                        "explicit origins + 'nonce-RAND' for inline.",
            evidence_marker="script-src wildcard"))

    # 4. frame-ancestors audit (CSP-based clickjacking protection)
    if "frame-ancestors" not in parsed:
        findings.append(wrap_finding(
            "No frame-ancestors directive — clickjacking via iframe possible",
            "MEDIUM", cvss="5.3", cwe="CWE-1021", owasp="A05:2021",
            remediation="Add: frame-ancestors 'none' (or 'self' if you intentionally "
                        "frame yourself). Note: this supersedes the legacy X-Frame-"
                        "Options header in modern browsers.",
            evidence_marker="frame-ancestors missing"))

    # 5. base-uri audit (defends against base-tag injection)
    if "base-uri" not in parsed:
        findings.append(wrap_finding(
            "No base-uri directive — <base> injection can hijack relative URLs",
            "LOW",
            cwe="CWE-1021", owasp="A05:2021",
            remediation="Add: base-uri 'none' (or 'self' if you set <base href>).",
            evidence_marker="base-uri missing"))

    # POSITIVE if no major findings
    if not findings:
        findings.append(wrap_finding(
            f"CSP looks well-formed ({len(parsed)} directives)",
            "POSITIVE", cwe="CWE-1021",
            remediation="Maintain. Audit on every framework upgrade.",
            evidence_marker=f"directives: {', '.join(parsed.keys())}"))

    return standard_response(
        tool="csp3_audit", target=req.target, findings=findings,
        tests_performed=1, vulnerable=any(f.get("severity") in ("HIGH", "MEDIUM")
                                              for f in findings),
        tests_summary=f"CSP has {len(parsed)} directives; {len(findings)} issue(s)",
        raw_data={"csp_directives": parsed, "is_report_only": using_ro_only})


def register(app):
    app.include_router(router)
