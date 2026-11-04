"""Security Headers scanner — 9 critical HTTP security headers.

VL-VERIFY: scanner audits headers on the homepage. SPA homepages ARE the
real homepages whose headers we want to evaluate. Canary check is a
context stamp only - no behavior change.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.webapp._webapp_common import vuln_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify
router = APIRouter()

def _csp(h):
    # SEVERITY-V2 — a missing CSP is a defense-in-depth gap, not a direct
    # data-disclosure flaw: no confidentiality impact on its own. Rated
    # MEDIUM with a C:N-style score, not HIGH (prior 7.5 was inflated).
    if "content-security-policy" not in {k.lower() for k in h}:
        return wrap_finding("No Content-Security-Policy header — XSS mitigation absent (defense-in-depth gap)",
            "MEDIUM", cvss="5.3", cwe="CWE-693", owasp="A05:2021",
            remediation='Add a CSP, e.g. "default-src \'self\'; script-src \'self\'".',
            evidence_marker="response missing Content-Security-Policy header")
def _hsts(h, https):
    # SEVERITY-V2 — missing HSTS enables a downgrade only under an active
    # MITM; it discloses nothing by itself. MEDIUM, not HIGH (prior 7.4).
    if https and "strict-transport-security" not in {k.lower() for k in h}:
        return wrap_finding("No HSTS on HTTPS — downgrade attacks possible",
            "MEDIUM", cvss="5.3", cwe="CWE-319", owasp="A02:2021",
            remediation='Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
            evidence_marker="HTTPS site missing Strict-Transport-Security")
# DEDUP-V2 — clickjacking (X-Frame-Options / CSP frame-ancestors) is owned by
# the dedicated clickjacking.py module at a single MEDIUM severity. The old
# _xfo() check here stamped the same issue a second time at HIGH, so the
# report showed clickjacking twice at two severities. Removed on purpose.
def _xcto(h):
    for k, v in h.items():
        if k.lower() == "x-content-type-options":
            if "nosniff" in (v or "").lower(): return None
            return wrap_finding(f"X-Content-Type-Options present but not 'nosniff': {v!r}",
                "MEDIUM", cvss="4.3", cwe="CWE-693", owasp="A05:2021",
                remediation="Set to exactly 'X-Content-Type-Options: nosniff'.",
                evidence_marker=f"X-Content-Type-Options: {v}")
    return wrap_finding("Missing 'X-Content-Type-Options: nosniff' — MIME-sniffing possible",
        "MEDIUM", cvss="4.3", cwe="CWE-693", owasp="A05:2021",
        remediation="Set header 'X-Content-Type-Options: nosniff'.",
        evidence_marker="response missing X-Content-Type-Options header")
def _ref(h):
    if "referrer-policy" not in {k.lower() for k in h}:
        return wrap_finding("No Referrer-Policy header — full referrer leaks",
            "LOW", cvss="3.1", cwe="CWE-200", owasp="A01:2021",
            remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
            evidence_marker="response missing Referrer-Policy header")
def _perm(h):
    hk = {k.lower() for k in h}
    if "permissions-policy" not in hk and "feature-policy" not in hk:
        return wrap_finding("No Permissions-Policy header — browser features not restricted",
            "LOW", cvss="3.1", cwe="CWE-693", owasp="A05:2021",
            remediation="Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()'.",
            evidence_marker="response missing Permissions-Policy header")
def _srv(h):
    for k, v in h.items():
        if k.lower() == "server" and v and any(c.isdigit() for c in v):
            return wrap_finding(f"Server header reveals version: {v!r}",
                "LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
                remediation="Strip version info from Server header.",
                evidence_marker=f"Server: {v}")
def _xpb(h):
    for k, v in h.items():
        if k.lower() == "x-powered-by" and v:
            return wrap_finding(f"X-Powered-By reveals tech: {v!r}",
                "LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
                remediation="Disable X-Powered-By in framework/server config.",
                evidence_marker=f"X-Powered-By: {v}")

def scan_security_headers(req, payload):
    url = web_url(req.target)
    spa = detect_spa_catchall_sync(url.rstrip("/"))
    r = safe_get(url, req=req, allow_redirects=True, timeout=10)
    if r is None:
        return standard_response(tool="security_headers", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")
    https = str(r.url).startswith("https://")
    h = dict(r.headers)
    checks = [_csp(h), _hsts(h, https), _xcto(h), _ref(h), _perm(h), _srv(h), _xpb(h)]
    findings = [c for c in checks if c]
    if not findings:
        findings.append(wrap_finding(
            "All audited security headers are present and correctly configured.",
            severity="POSITIVE", cvss="0.0", cwe="N/A", owasp="A05:2021",
            remediation="No action needed; keep enforcing the security-header baseline.",
            evidence_marker=f"{len(checks)} header checks passed"))
    return vuln_response(tool="security_headers", target=req.target,
        findings=findings, tested=len(checks),
        what_checked="HTTP security headers (CSP, HSTS, XCTO, Referrer, Permissions, Server, X-Powered-By); clickjacking/X-Frame-Options is covered by the clickjacking module",
        tests_summary="Header checks: CSP, HSTS, XCTO, Referrer, Permissions, Server, X-Powered-By",
        raw_data={"security_headers": {"is_https": https,
                                          "headers_seen": list(h.keys()),
                                          "spa_catchall": spa["is_spa"]}})

@router.post("/api/webapp/scan/security_headers")
@vl_turbo()
@vl_verify()
def ep_sh(req: ScanRequest, payload=Depends(verify_scan_quota)):
    return scan_security_headers(req, payload)
@router.post("/api/webapp/scan/headers")
@vl_turbo()
@vl_verify()
def ep_h(req: ScanRequest, payload=Depends(verify_scan_quota)):
    r = scan_security_headers(req, payload)
    if isinstance(r, dict): r["tool"] = "headers"
    return r
def register(app): app.include_router(router)
