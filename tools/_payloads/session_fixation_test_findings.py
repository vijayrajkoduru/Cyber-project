"""session_fixation_test - findings rules.

Severity model:
  HIGH     - login succeeded but session ID stayed identical -> session fixation
  INFO     - login appeared to fail / no session cookie / missing input
  POSITIVE - login worked AND session ID rotated
"""


def rule_high_session_not_rotated(s):
    if not s.get("sf_session_fixed"):
        return None
    return {
        "name": f"Session fixation possible: cookie {s.get('sf_session_cookie_name', '?')!r} not rotated after authentication",
        "severity": "HIGH",
        "cvss": "8.0",
        "cwe": "CWE-384",
        "owasp": "A07:2021",
        "evidence": (
            f"Pre-login cookie {s.get('sf_session_cookie_name', '?')}={s.get('sf_pre_cookie_redacted', '?')} "
            f"and post-login value {s.get('sf_post_cookie_redacted', '?')} are IDENTICAL. "
            "Pre-status=" + str(s.get('sf_pre_status')) + ", post-status=" + str(s.get('sf_post_status')) + ". "
            "An attacker who pre-sets this cookie value in the victim's browser (XSS, MITM, "
            "physical access) will share their authenticated session - classic session fixation."
        ),
        "remediation": (
            "1. Regenerate the session ID server-side ON every authentication event "
            "(login, MFA-pass, role change). PHP: session_regenerate_id(true). "
            "Django: request.session.cycle_key(). Express: req.session.regenerate(). "
            "Rails: reset_session. ASP.NET: Session.Abandon() + new Session.SessionID. "
            "2. Mark the session cookie HttpOnly + Secure + SameSite=Lax. "
            "3. Set short idle-timeout (15 min) and absolute-timeout (8h) server-side. "
            "4. Re-run this scan after the fix - pre/post values MUST differ."
        ),
    }


def rule_input_missing(s):
    if not s.get("sf_input_missing"):
        return None
    return {
        "name": "Session fixation test skipped - missing target or credentials",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe requires ScanRequest.target = login URL AND options.username + options.password. "
            "Without all three the canonical fixation flow cannot run."
        ),
        "remediation": (
            "Re-run with the login form URL as target and a real test-account credential pair "
            "in options.username/password. Tip: create a throwaway customer account for repeat scans."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("sf_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required for the cookie-jar test flow.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_no_session_cookie(s):
    if not s.get("sf_no_session_cookie"):
        return None
    return {
        "name": "No session-style cookie detected in either response",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"Pre-login cookies: {s.get('sf_pre_cookies') or '[]'}. "
            f"Post-login cookies: {s.get('sf_post_cookies') or '[]'}. "
            "None matched typical session-name patterns (PHPSESSID/sessionid/jsessionid/auth/etc)."
        ),
        "remediation": (
            "If the app uses an opaque cookie name, pass it via options.session_cookie_name. "
            "If it uses token-only auth (Bearer in localStorage), session fixation is N/A - "
            "but ensure tokens are rotated on login (and httpOnly+SameSite cookies guard the refresh)."
        ),
    }


def rule_login_failed(s):
    if s.get("sf_input_missing") or s.get("sf_httpx_missing"):
        return None
    if s.get("sf_no_session_cookie"):
        return None
    if s.get("sf_login_worked"):
        return None
    err = s.get("sf_error")
    return {
        "name": "Could not verify login - session fixation result inconclusive",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"Pre-status={s.get('sf_pre_status')}, post-status={s.get('sf_post_status')}, "
            f"login marker present={s.get('sf_body_marker_present')}. "
            + (f"Error: {err}. " if err else "")
            + "If the test credentials are correct, the success_marker option may need tuning."
        ),
        "remediation": (
            "Set options.success_marker to a string present in the post-login response body "
            "(e.g. 'Welcome', 'logout', 'dashboard'). Re-run."
        ),
    }


def rule_positive(s):
    if s.get("sf_input_missing"):
        return None
    if s.get("sf_httpx_missing"):
        return None
    if s.get("sf_no_session_cookie"):
        return None
    if not s.get("sf_login_worked"):
        return None
    if s.get("sf_session_fixed"):
        return None
    return {
        "name": f"Session ID correctly rotated after login (cookie {s.get('sf_session_cookie_name', '?')!r})",
        "severity": "POSITIVE",
        "cwe": "CWE-384",
        "owasp": "A07:2021",
        "evidence": (
            f"Pre-login value {s.get('sf_pre_cookie_redacted', '?')} differs from post-login "
            f"value {s.get('sf_post_cookie_redacted', '?')}. Session fixation NOT possible "
            "via cookie pre-set. Login marker observed: " + str(s.get('sf_body_marker_present')) + "."
        ),
        "remediation": (
            "Keep the rotation in place. Also confirm the cookie carries Secure + HttpOnly + "
            "SameSite=Lax/Strict, and that logout invalidates the session server-side."
        ),
    }


SESSION_FIXATION_TEST_FINDING_RULES = [
    rule_high_session_not_rotated,
    rule_input_missing,
    rule_httpx_missing,
    rule_no_session_cookie,
    rule_login_failed,
    rule_positive,
]
