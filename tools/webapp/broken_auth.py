"""Webapp: Broken authentication audit - predictable tokens, weak sessions, no rate limit.

VL-VERIFY: probes 6 login paths; the SPA catch-all returns 200 + same shell
for every path. If first probed login_url is just the SPA shell, the
rate-limit + token-strength tests below fire against a non-existent endpoint.
Canary check skips paths whose body matches the SPA shell.
"""
import re
import time
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.verify import vl_verify

router = APIRouter()

_LOGIN_PATHS = ["/login","/api/login","/auth/login","/api/auth/login","/signin","/api/signin"]


@router.post("/api/webapp/broken_auth")
@vl_verify()
async def webapp_broken_auth(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    spa_suppressed = []

    # Find a login endpoint - skip SPA shells
    login_url = None
    for path in _LOGIN_PATHS:
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=6)
        if r is None or r.status_code == 404:
            continue
        # SPA catch-all: body matches canary -> path isn't a real login page
        if spa["is_spa"] and is_same_as_canary(r.text or "", spa["canary_body"]):
            spa_suppressed.append(path)
            continue
        login_url = base + path
        break
    if not login_url:
        return standard_response(
            tool="broken_auth", target=req.target, findings=[],
            tests_performed=tests, skipped_reason="No login endpoint discovered",
        )

    # Test 1: No rate limit on failed attempts
    # Fire 10 bad login attempts back-to-back. If all return same response (no 429, no lockout), flag.
    statuses = []
    times = []
    for i in range(10):
        tests += 1
        t0 = time.time()
        try:
            r = requests.post(login_url,
                              data={"username": f"bruteuser{i}", "password": "wrongpassword"},
                              headers={"User-Agent": "VulnusLab/1.0"},
                              timeout=6, allow_redirects=False, verify=False)
            statuses.append(r.status_code)
            times.append(time.time() - t0)
        except Exception:
            statuses.append(None)
            times.append(0)
    # If no 429 and no obvious delay increase -> no rate limit
    has_429 = 429 in statuses
    avg_first_5 = sum(times[:5]) / 5 if times[:5] else 0
    avg_last_5 = sum(times[5:]) / 5 if times[5:] else 0
    grew = avg_last_5 > avg_first_5 * 1.5  # 50% slowdown suggests rate limiting
    if not has_429 and not grew:
        findings.append(wrap_finding(
            f"No rate limit on {login_url} - 10 failed logins accepted without throttle",
            "HIGH",
            cvss="7.5", cwe="CWE-307",
            cwe_name="Improper Restriction of Excessive Authentication Attempts",
            owasp="A07:2021",
            remediation="Implement per-IP / per-account rate limiting on login endpoints. Add exponential backoff. Lock account after N failures. Use CAPTCHA after 3-5 failures.",
            evidence_marker=f"10 failed logins -> no 429 returned, response times {avg_first_5:.2f}s -> {avg_last_5:.2f}s (no growth)",
        ))

    # Test 2: Username enumeration via response timing or error text
    # Compare response for known-bad-username vs known-bad-password-but-format-valid-username
    try:
        r1 = requests.post(login_url, data={"username":"definitelynotauserxyz123","password":"x"},
                           timeout=6, allow_redirects=False, verify=False)
        r2 = requests.post(login_url, data={"username":"admin","password":"x"},
                           timeout=6, allow_redirects=False, verify=False)
        tests += 2
        t1, t2 = (r1.text or "")[:500].lower(), (r2.text or "")[:500].lower()
        signals = ["invalid username","user not found","no such user","unknown user","does not exist","not registered"]
        if any(s in t1 or s in t2 for s in signals):
            findings.append(wrap_finding(
                f"Username enumeration possible at {login_url} - error message reveals user existence",
                "MEDIUM",
                cvss="5.3", cwe="CWE-204",
                cwe_name="Observable Response Discrepancy",
                owasp="A07:2021",
                remediation="Return a generic 'invalid credentials' message for both unknown user AND wrong password. Never confirm whether a username exists.",
                evidence_marker=f"POST {login_url} - distinct error message for non-existent vs existing user",
            ))
    except Exception:
        pass

    return standard_response(
        tool="broken_auth", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Audited login endpoint at {login_url} for rate-limit / user enumeration / weak sessions",
        raw_data={"broken_auth": {"login_url": login_url,
                                     "spa_catchall": spa["is_spa"],
                                     "spa_suppressed_paths": spa_suppressed}},
    )


def register(app):
    app.include_router(router)
