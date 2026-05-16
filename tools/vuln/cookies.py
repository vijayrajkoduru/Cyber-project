"""Cookie Security — Secure / HttpOnly / SameSite analysis."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_SESSION = re.compile(r"(sess|session|sid|auth|token|jwt|csrf|xsrf|connect\.sid)", re.I)

@router.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(tool="cookies", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")
    is_https = str(r.url).startswith("https://")
    findings, analyzed = [], []
    for c in r.cookies:
        is_session = bool(_SESSION.search(c.name))
        httponly = bool(c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"))
        same_site = None
        if hasattr(c, "_rest"):
            for k, v in c._rest.items():
                if k.lower() == "samesite": same_site = v; break
        analyzed.append({"name": c.name, "secure": c.secure, "httponly": httponly,
                         "samesite": same_site, "session_like": is_session})
        if is_https and not c.secure:
            findings.append(wrap_finding(
                f"Cookie '{c.name}' missing Secure flag on HTTPS",
                "HIGH" if is_session else "MEDIUM",
                cvss="6.5" if is_session else "5.0", cwe="CWE-614", owasp="A02:2021",
                remediation="Add Secure flag so cookie never goes over plain HTTP.",
                evidence_marker=f"cookie={c.name} secure=False on HTTPS"))
        if is_session and not httponly:
            findings.append(wrap_finding(
                f"Session cookie '{c.name}' missing HttpOnly — XSS can steal it",
                "HIGH", cvss="7.0", cwe="CWE-1004", owasp="A07:2021",
                remediation="Add HttpOnly so JavaScript can't read it.",
                evidence_marker=f"cookie={c.name} httponly=False session-like"))
        if is_session and (not same_site or same_site.lower() == "none"):
            findings.append(wrap_finding(
                f"Session cookie '{c.name}' has weak SameSite ({same_site or 'unset'})",
                "MEDIUM", cvss="5.5", cwe="CWE-352", owasp="A01:2021",
                remediation="Set SameSite=Lax or Strict on session cookies.",
                evidence_marker=f"cookie={c.name} samesite={same_site or 'unset'}"))
    return standard_response(tool="cookies", target=req.target,
        findings=findings, tests_performed=max(len(analyzed), 1),
        tests_summary=f"Analyzed {len(analyzed)} cookie(s) for Secure/HttpOnly/SameSite",
        raw_data={"cookies": {"analyzed": analyzed, "is_https": is_https}})
def register(app): app.include_router(router)
