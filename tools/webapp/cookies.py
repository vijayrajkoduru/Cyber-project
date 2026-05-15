"""Cookie security scanner — Secure/HttpOnly/SameSite analysis."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()


@router.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="cookies", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}",
        )
    is_https = str(r.url).startswith("https://")
    findings = []
    cookies_analyzed = []
    for c in r.cookies:
        is_session = bool(re.search(r"(sess|session|sid|auth|token|jwt|csrf)", c.name, re.I))
        httponly = bool(c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"))
        same_site = None
        if hasattr(c, "_rest"):
            for k, v in c._rest.items():
                if k.lower() == "samesite":
                    same_site = v
                    break
        cookies_analyzed.append({"name": c.name, "secure": c.secure, "httponly": httponly,
                                  "same_site": same_site, "is_session_like": is_session})
        if is_https and not c.secure:
            findings.append(wrap_finding(
                f"Cookie '{c.name}' missing Secure flag",
                "HIGH" if is_session else "MEDIUM",
                cwe="CWE-614", owasp="A02:2021",
                evidence_marker=f"cookie={c.name} secure=False on HTTPS site",
                remediation="Add the Secure flag to all cookies served over HTTPS.",
                cvss="6.5" if is_session else "5.0",
                tests_performed=1,
            ))
        if is_session and not httponly:
            findings.append(wrap_finding(
                f"Session cookie '{c.name}' missing HttpOnly — XSS can steal it",
                "HIGH", cwe="CWE-1004", owasp="A07:2021",
                evidence_marker=f"cookie={c.name} httponly=False (session-like)",
                remediation="Set HttpOnly on all session/auth cookies.",
                cvss="7.0",
                tests_performed=1,
            ))
        if is_session and (not same_site or same_site.lower() == "none"):
            findings.append(wrap_finding(
                f"Session cookie '{c.name}' has weak SameSite policy ({same_site or 'unset'})",
                "MEDIUM", cwe="CWE-352", owasp="A01:2021",
                evidence_marker=f"cookie={c.name} samesite={same_site or 'unset'}",
                remediation="Set SameSite=Lax (default) or Strict on session cookies.",
                cvss="5.5",
                tests_performed=1,
            ))
    return standard_response(
        tool="cookies", target=req.target, findings=findings,
        tests_performed=max(len(cookies_analyzed), 1),
        tests_summary=f"Analyzed {len(cookies_analyzed)} cookie(s) for Secure/HttpOnly/SameSite",
        raw_data={"cookies": {"analyzed": cookies_analyzed, "is_https": is_https}},
    )


def register(app):
    app.include_router(router)
