"""HTTP security headers analysis.

Active verification: GET the target, inspect response headers and
cookie attributes. Confirmed findings only — every flag is a direct
observation of the returned HTTP response.
"""
import re
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


@router.post("/api/scan/security_headers")
async def scan_security_headers(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0

    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="security_headers", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}",
        )

    h = {k.lower(): v for k, v in r.headers.items()}
    is_https = str(r.url).startswith("https://")
    raw = {"final_url": str(r.url), "status": r.status_code, "headers": dict(r.headers)}

    # Test 1 — CSP
    tests += 1
    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append(wrap_finding(
            "No Content-Security-Policy header — XSS mitigation absent",
            "HIGH", cwe="CWE-1021", owasp="A05:2021",
            evidence_marker=f"Response from {r.url}: CSP header missing",
            remediation="Add a CSP, e.g. \"default-src 'self'; script-src 'self'\".",
            tests_performed=1,
        ))

    # Test 2 — HSTS (only meaningful on HTTPS)
    tests += 1
    if is_https and not h.get("strict-transport-security"):
        findings.append(wrap_finding(
            "HTTPS response missing Strict-Transport-Security — TLS downgrade risk",
            "HIGH", cwe="CWE-319", owasp="A02:2021",
            evidence_marker=f"Response from {r.url}: HSTS header missing",
            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            tests_performed=1,
        ))

    # Test 3 — Clickjacking (XFO or CSP frame-ancestors)
    tests += 1
    xfo = h.get("x-frame-options", "").lower()
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(wrap_finding(
            "No X-Frame-Options and no CSP frame-ancestors — clickjacking possible",
            "HIGH", cwe="CWE-1021", owasp="A05:2021",
            evidence_marker=f"Response from {r.url}: no XFO, no frame-ancestors",
            remediation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN'), or 'frame-ancestors' in CSP.",
            tests_performed=1,
        ))

    # Test 4 — X-Content-Type-Options
    tests += 1
    if h.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(wrap_finding(
            "Missing 'X-Content-Type-Options: nosniff' — MIME-sniffing attacks possible",
            "MEDIUM", cwe="CWE-693",
            evidence_marker=f"x-content-type-options={h.get('x-content-type-options', '<missing>')}",
            remediation="Set header 'X-Content-Type-Options: nosniff'.",
            tests_performed=1,
        ))

    # Test 5 — Referrer-Policy
    tests += 1
    if not h.get("referrer-policy"):
        findings.append(wrap_finding(
            "No Referrer-Policy header — full referrer leaks to third parties",
            "LOW", cwe="CWE-200",
            evidence_marker=f"Response from {r.url}: Referrer-Policy missing",
            remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
            tests_performed=1,
        ))

    # Test 6 — Permissions-Policy
    tests += 1
    if not (h.get("permissions-policy") or h.get("feature-policy")):
        findings.append(wrap_finding(
            "No Permissions-Policy header — browser features not restricted",
            "LOW", cwe="CWE-693",
            evidence_marker=f"Response from {r.url}: Permissions-Policy missing",
            remediation="Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()'.",
            tests_performed=1,
        ))

    # Test 7 — Server header version disclosure
    tests += 1
    server = h.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(wrap_finding(
            f"Server header reveals software version: {server!r}",
            "LOW", cwe="CWE-200",
            evidence_marker=f"server={server}",
            remediation="Strip version info from the Server header or remove it entirely.",
            tests_performed=1,
        ))

    # Test 8 — X-Powered-By disclosure
    tests += 1
    xpb = h.get("x-powered-by", "")
    if xpb:
        findings.append(wrap_finding(
            f"X-Powered-By header discloses framework: {xpb!r}",
            "LOW", cwe="CWE-200",
            evidence_marker=f"x-powered-by={xpb}",
            remediation="Remove the X-Powered-By header from the application or reverse proxy.",
            tests_performed=1,
        ))

    # Test 9 — Cookie flags
    tests += 1
    cookies_inspected = []
    for cookie in r.cookies:
        is_session = bool(re.search(r"(sess|session|sid|auth|token|jwt)", cookie.name, re.I))
        httponly = bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"))
        cookies_inspected.append({
            "name": cookie.name, "secure": cookie.secure,
            "httponly": httponly, "session_like": is_session,
        })
        if is_https and not cookie.secure:
            findings.append(wrap_finding(
                f"Cookie '{cookie.name}' missing Secure flag",
                "HIGH" if is_session else "MEDIUM",
                cwe="CWE-614", owasp="A02:2021",
                evidence_marker=f"cookie={cookie.name} secure=False",
                remediation="Set the Secure flag on cookies served over HTTPS.",
                tests_performed=1,
            ))
        if is_session and not httponly:
            findings.append(wrap_finding(
                f"Session cookie '{cookie.name}' missing HttpOnly flag — XSS can steal it",
                "HIGH", cwe="CWE-1004", owasp="A07:2021",
                evidence_marker=f"cookie={cookie.name} httponly=False",
                remediation="Set HttpOnly on all session/auth cookies.",
                tests_performed=1,
            ))
    raw["cookies"] = cookies_inspected

    return standard_response(
        tool="security_headers", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary="9 header checks: CSP, HSTS, XFO, XCTO, Referrer, Permissions, Server, X-Powered-By, Cookies",
        raw_data={"security_headers": raw},
    )


def register(app):
    app.include_router(router)
