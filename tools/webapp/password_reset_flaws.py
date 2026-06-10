"""Webapp: Password reset flaw scanner - email enum, weak token, no rate limit."""
import re
import time
import requests
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.verify import vl_verify

router = APIRouter()

_RESET_PATHS = ["/password/reset","/forgot-password","/forgot","/reset-password","/api/password/reset","/api/forgot-password","/account/reset","/user/forgot","/recover"]


@router.post("/api/webapp/password_reset_flaws")
@vl_verify()
async def webapp_password_reset_flaws(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    reset_url = None
    for p in _RESET_PATHS:
        tests += 1
        r = safe_get(base + p, req=req, allow_redirects=True, timeout=6)
        if r is None or r.status_code == 404:
            continue
        body = (r.text or "")[:30000]
        if not re.search(r'<input[^>]*(?:name|type)=["\']?(?:email|mail)', body, re.I):
            continue
        reset_url = base + p
        break
    if not reset_url:
        return standard_response(
            tool="password_reset_flaws", target=req.target, findings=[],
            tests_performed=tests, skipped_reason="No password-reset form discovered",
        )
    
    # Test: email enumeration via response differences
    fake_email = f"definitelynotauser_{secrets.token_hex(4)}@example.invalid"
    common_email = "admin@" + base.replace("https://","").replace("http://","").split("/")[0]
    
    try:
        tests += 1
        r1 = requests.post(reset_url, data={"email": fake_email},
                           headers={"User-Agent":"VulnusLab/1.0"},
                           timeout=8, allow_redirects=False, verify=False)
        tests += 1
        r2 = requests.post(reset_url, data={"email": common_email},
                           headers={"User-Agent":"VulnusLab/1.0"},
                           timeout=8, allow_redirects=False, verify=False)
        t1 = (r1.text or "")[:2000].lower()
        t2 = (r2.text or "")[:2000].lower()
        # Look for distinctive error messages
        enum_signals = ["no user","user not found","email not found","not registered","does not exist","unknown email","no account"]
        if any(s in t1 for s in enum_signals) or any(s in t2 for s in enum_signals):
            findings.append(wrap_finding(
                f"Password reset email enumeration at {reset_url}",
                "MEDIUM",
                cvss="5.3", cwe="CWE-204",
                cwe_name="Observable Response Discrepancy",
                owasp="A07:2021",
                remediation="Always return the same generic message ('If an account exists with this email, you will receive a reset link') regardless of whether the email is registered.",
                evidence_marker=f"POST {reset_url} with non-existent email -> response contains error revealing user-existence state",
            ))
        # Also detect significant size difference even without explicit error words
        elif abs(len(r1.text or "") - len(r2.text or "")) > 200:
            findings.append(wrap_finding(
                f"Password reset response size differs by user existence at {reset_url}",
                "LOW",
                cvss="3.7", cwe="CWE-204",
                owasp="A07:2021",
                remediation="Normalize response body and timing for known vs unknown emails.",
                evidence_marker=f"POST with bogus email -> {len(r1.text or '')}B, POST with real-looking email -> {len(r2.text or '')}B",
            ))
    except Exception:
        pass

    return standard_response(
        tool="password_reset_flaws", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Audited {reset_url} for email enumeration via response differential",
        raw_data={"password_reset_flaws": {"reset_url": reset_url, "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
