"""Webapp: Session fixation - cookie should rotate after login state change."""
import re
import requests
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

_LOGIN_PATHS = ["/login","/signin","/auth/login","/api/login","/api/auth/login"]


@router.post("/api/webapp/session_fixation")
@vl_verify()
async def webapp_session_fixation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    
    # Find login form
    login_url = None
    for p in _LOGIN_PATHS:
        tests += 1
        try:
            r = requests.get(base + p, timeout=8, allow_redirects=True, verify=False,
                             headers={"User-Agent":"VulnusLab/1.0"})
        except Exception:
            continue
        if r.status_code == 200 and re.search(r'<input[^>]*type=["\']?password', r.text or "", re.I):
            login_url = base + p
            break
    if not login_url:
        return standard_response(
            tool="session_fixation", target=req.target, findings=[],
            tests_performed=tests, skipped_reason="No login form discovered",
        )
    
    # 1) Fetch login page - get any session cookie issued pre-auth
    try:
        r1 = requests.get(login_url, timeout=8, allow_redirects=False, verify=False,
                          headers={"User-Agent":"VulnusLab/1.0"})
    except Exception:
        return standard_response(tool="session_fixation", target=req.target, findings=[],
                                 tests_performed=tests, skipped_reason="Could not fetch login page")
    pre_cookies = {c.name: c.value for c in r1.cookies}
    session_cookie_names = [n for n in pre_cookies if any(k in n.lower() for k in ("session","sess","sid","jsessionid","phpsessid","asp.net","laravel_session","connect.sid"))]
    if not session_cookie_names:
        return standard_response(tool="session_fixation", target=req.target, findings=[],
                                 tests_performed=tests, skipped_reason="No session cookie set pre-login")
    
    # 2) Attempt bogus login (won't succeed - we just want to see if session_id is rotated regardless)
    tests += 1
    try:
        r2 = requests.post(login_url,
                           data={"username":"bruteforce_canary","password":secrets.token_urlsafe(16)},
                           cookies=pre_cookies, timeout=8, allow_redirects=False, verify=False,
                           headers={"User-Agent":"VulnusLab/1.0"})
        post_cookies = {c.name: c.value for c in r2.cookies}
    except Exception:
        post_cookies = {}
    
    # If session cookie is the SAME after the auth-attempt request (and no new one issued), it's fixation-vulnerable.
    # NOTE: This is a SUSPECTED finding - confirming requires actual successful login. Documented as such.
    same_cookie = any(n in post_cookies and post_cookies[n] == pre_cookies[n] for n in session_cookie_names)
    no_new = not any(n not in pre_cookies for n in post_cookies if any(k in n.lower() for k in ("session","sess","sid")))
    if same_cookie and no_new:
        findings.append(wrap_finding(
            f"Suspected session fixation - server does not rotate session cookie on auth state change",
            "MEDIUM",
            cvss="6.1", cwe="CWE-384",
            cwe_name="Session Fixation",
            owasp="A07:2021",
            remediation=("Regenerate the session ID upon successful login (and on privilege change). "
                         "In Java: request.getSession().invalidate(); request.getSession(true). "
                         "In PHP: session_regenerate_id(true). In Express: regenerate session via "
                         "passport's req.login()."),
            evidence_marker=f"Pre-login cookie {session_cookie_names[0]}={pre_cookies[session_cookie_names[0]][:12]}... persists after auth attempt",
        ))

    return standard_response(
        tool="session_fixation", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {login_url} for session cookie rotation on auth state change",
        raw_data={"session_fixation": {"login_url": login_url, "session_cookies": session_cookie_names}},
    )


def register(app):
    app.include_router(router)
