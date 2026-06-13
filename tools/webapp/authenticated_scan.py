"""Webapp: Authenticated scanning support - Phase 1 (login form auditor).

Discovers login forms at common paths and audits their security:
- CSRF token presence
- HTTPS submission
- Password field autocomplete restrictions
- Form action target

Phase 2 (TODO): Actually log in, save session cookie, re-run scanners.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.verify import vl_verify

router = APIRouter()

_LOGIN_PATHS = [
    "/login","/signin","/sign-in","/auth/login","/user/login","/api/login",
    "/account/login","/users/sign_in","/admin/login","/admin",
]


@router.post("/api/webapp/authenticated_scan")
@vl_verify()
async def webapp_authenticated_scan(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    discovered = []
    tests = len(_LOGIN_PATHS)

    async def _probe(path):
        url = base + path
        r = await asyncio.to_thread(safe_get, url, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code != 200:
            return None
        body = (r.text or "")[:50000]
        if not re.search(r'<input[^>]*type=["\']?password["\']?', body, re.I):
            return None
        return (path, r.status_code, body)

    results = await asyncio.gather(
        *[_probe(path) for path in _LOGIN_PATHS],
        return_exceptions=True)
    for res in results:
        if isinstance(res, BaseException) or res is None:
            continue
        path, status_code, body = res
        discovered.append({"url": path, "status": status_code})

        has_csrf = bool(re.search(r'name=["\']?(?:csrf|_token|authenticity_token|__RequestVerificationToken)', body, re.I))
        if not has_csrf:
            findings.append(wrap_finding(
                f"Login form at {path} lacks CSRF token",
                "MEDIUM",
                cvss="5.4", cwe="CWE-352",
                cwe_name="Cross-Site Request Forgery",
                owasp="A01:2021",
                remediation="Add a CSRF token to the login form and validate it server-side.",
                evidence_marker=f"GET {path} - login form contains password field but no CSRF token",
            ))

        m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I)
        if m and m.group(1).startswith("http://"):
            findings.append(wrap_finding(
                f"Login form at {path} submits over HTTP (not HTTPS)",
                "HIGH",
                cvss="7.4", cwe="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                owasp="A02:2021",
                remediation="Submit login forms over HTTPS only.",
                evidence_marker=f"Form action: {m.group(1)}",
            ))

        pw = re.search(r'<input[^>]*type=["\']?password["\']?[^>]*>', body, re.I)
        if pw and not re.search(r'autocomplete=["\']?(?:off|new-password|current-password)', pw.group(0), re.I):
            findings.append(wrap_finding(
                f"Login form at {path} - password field has no autocomplete restriction",
                "LOW",
                cvss="2.1", cwe="CWE-200",
                cwe_name="Information Exposure",
                owasp="A05:2021",
                remediation='Add autocomplete="off" or autocomplete="current-password" to the password field.',
                evidence_marker=f"Password field: {pw.group(0)[:120]}",
            ))

    if not discovered:
        return standard_response(
            tool="authenticated_scan", target=req.target, findings=[],
            tests_performed=tests,
            skipped_reason="No login form discovered at common paths",
            raw_data={"authenticated_scan": {"checked_paths": _LOGIN_PATHS,
                                                 "spa_catchall": spa["is_spa"]}},
        )

    if not findings:
        findings.append(wrap_finding(
            "Login form(s) audited clean — CSRF token present, HTTPS submission, "
            "autocomplete restricted",
            "POSITIVE", cwe="CWE-287",
            remediation="Maintain CSRF protection, HTTPS-only form action, and "
                        "autocomplete restrictions on credential fields. Re-test after "
                        "login-page changes.",
            evidence_marker=f"audited {len(discovered)} login form(s) for "
                            "CSRF / HTTPS / autocomplete; no defect found"))
    return standard_response(
        tool="authenticated_scan", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Audited {len(discovered)} login form(s) for CSRF / HTTPS / autocomplete",
        raw_data={"authenticated_scan": {"login_forms": discovered,
                                            "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
