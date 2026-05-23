"""Cookie Security -- Secure / HttpOnly / SameSite analysis.

Framework-aware: many web frameworks ship a CSRF cookie that is
INTENTIONALLY JavaScript-readable (the JS reads it and echoes the value
into an X-CSRF-Token header on every request). Flagging those as
"missing HttpOnly" is a false positive that costs customer trust.
The Secure flag and SameSite checks still apply -- CSRF cookies should
still be Secure on HTTPS.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.webapp._webapp_common import vuln_response, precheck_target
router = APIRouter()
_SESSION = re.compile(r"(sess|session|sid|auth|token|jwt|csrf|xsrf|connect\.sid)", re.I)

# Framework CSRF cookies that MUST be JS-readable by design.
# Source: official docs for Laravel, Angular, Django, Rails, Express, ASP.NET.
_JS_READABLE_BY_DESIGN = {
    "xsrf-token",                    # Laravel, Angular ($http)
    "csrf-token",                    # Rails (cookie store)
    "_csrf",                         # Express / koa / hapi csrf middleware
    "csrftoken",                     # Django
    "csrf_token",                    # Flask-WTF / common Python frameworks
    "__requestverificationtoken",    # ASP.NET MVC
    "x-csrf-token",                  # Spring Security
    "ct0",                           # Twitter / X (csrf token cookie)
}


def _is_csrf_token_by_design(name: str) -> bool:
    """Match against the known-readable CSRF cookie names (case-insensitive)."""
    return name.lower() in _JS_READABLE_BY_DESIGN


@router.post("/api/webapp/scan/cookies")
def scan_cookies(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(tool="cookies", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")
    is_https = str(r.url).startswith("https://")
    findings, analyzed = [], []
    suppressed = []
    for c in r.cookies:
        is_session = bool(_SESSION.search(c.name))
        httponly = bool(c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"))
        same_site = None
        if hasattr(c, "_rest"):
            for k, v in c._rest.items():
                if k.lower() == "samesite": same_site = v; break
        is_csrf_by_design = _is_csrf_token_by_design(c.name)
        analyzed.append({"name": c.name, "secure": c.secure, "httponly": httponly,
                         "samesite": same_site, "session_like": is_session,
                         "csrf_by_design": is_csrf_by_design})
        # Secure flag -- always applies, including CSRF cookies
        if is_https and not c.secure:
            findings.append(wrap_finding(
                f"Cookie '{c.name}' missing Secure flag on HTTPS",
                "HIGH" if is_session else "MEDIUM",
                cvss="6.5" if is_session else "5.0", cwe="CWE-614", owasp="A02:2021",
                remediation="Add Secure flag so cookie never goes over plain HTTP.",
                evidence_marker=f"cookie={c.name} secure=False on HTTPS"))
        # HttpOnly -- skip framework CSRF cookies (designed to be JS-readable)
        if is_session and not httponly:
            if is_csrf_by_design:
                suppressed.append({"name": c.name, "check": "HttpOnly",
                                   "reason": "framework_csrf_token_must_be_js_readable"})
            else:
                findings.append(wrap_finding(
                    f"Session cookie '{c.name}' missing HttpOnly -- XSS can steal it",
                    "HIGH", cvss="7.0", cwe="CWE-1004", owasp="A07:2021",
                    remediation="Add HttpOnly so JavaScript can't read it.",
                    evidence_marker=f"cookie={c.name} httponly=False session-like"))
        # SameSite -- still applies to CSRF cookies (a CSRF cookie with
        # SameSite=None defeats its own purpose)
        if is_session and (not same_site or same_site.lower() == "none"):
            findings.append(wrap_finding(
                f"Session cookie '{c.name}' has weak SameSite ({same_site or 'unset'})",
                "MEDIUM", cvss="5.5", cwe="CWE-352", owasp="A01:2021",
                remediation="Set SameSite=Lax or Strict on session cookies.",
                evidence_marker=f"cookie={c.name} samesite={same_site or 'unset'}"))
    summary = f"Analyzed {len(analyzed)} cookie(s) for Secure/HttpOnly/SameSite"
    if suppressed:
        summary += f"; {len(suppressed)} framework-CSRF FP(s) suppressed"
    return vuln_response(tool="cookies", target=req.target,
        findings=findings, tested=max(len(analyzed), 1),
        what_checked="cookie Secure / HttpOnly / SameSite flags (framework-CSRF aware)",
        tests_summary=summary,
        raw_data={"cookies": {"analyzed": analyzed, "is_https": is_https,
                              "suppressed_fps": suppressed}})
def register(app): app.include_router(router)
