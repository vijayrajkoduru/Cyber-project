"""login_hardening_audit - finding rules (VL-METHOD aware).

Reads state populated by LoginHardeningAudit:
  - methodology_findings : list of detected weaknesses, each:
        {kind, detail, confidence}
  - login_url            : the login endpoint that was analysed
  - login_form_detected  : bool
  - target_base          : normalized base URL

ZERO-FALSE-POSITIVE CONTRACT
----------------------------
Every graded finding here corresponds to a condition OBSERVED on a real
HTTP response from the target's login surface:
  - cookie flags read from actual Set-Cookie headers
  - autocomplete attribute read from the actual login form HTML
  - transport scheme read from the actual login URL
  - absence of standard anti-automation headers on the actual response

This scanner NEVER submits real credentials and NEVER brute-forces. The
"rate limiting" signal is derived passively from response headers /
documented controls, NOT from hammering the login form, so we never claim
"no rate limit" as a graded finding (that would require active probing the
user did not authorize) — it is reported as INFO/advisory only.
"""


INTEL_FIELDS = [
    ("Target",              "target_base"),
    ("Login URL",           "login_url"),
    ("Login form detected", "login_form_detected"),
    ("Server fingerprint",  "fingerprint"),
    ("Cookie flags",        "cookie_flags"),
    ("Stage timings (ms)",  "stage_timings"),
    ("Stage errors",        "stage_errors"),
]


def _kinds(s, *want):
    out = []
    for f in (s.get("methodology_findings") or []):
        if f.get("kind") in want:
            out.append(f)
    return out


def rule_target_unreachable(s):
    sr = s.get("skipped_reason") or ""
    if "not reachable" not in sr and "no login" not in sr:
        return None
    if "no target" in sr:
        return None
    return {
        "name": "Login surface not reachable / no login form detected",
        "severity": "INFO",
        "evidence": sr,
        "remediation": ("Provide a direct login URL via options.login_path if the "
                        "login form lives behind a path the crawler did not reach. "
                        "Re-run so the scanner can assess credential-stuffing "
                        "resistance of the authentication form."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    sr = s.get("skipped_reason") or ""
    if "no target" not in sr:
        return None
    return {
        "name": "No target supplied - login hardening audit skipped",
        "severity": "INFO",
        "evidence": sr,
        "remediation": "Supply the application base URL on the request body.",
        "cwe": "CWE-1006",
    }


def rule_login_over_http(s):
    hits = _kinds(s, "login_over_http")
    if not hits:
        return None
    return {
        "name": "Login form submitted over cleartext HTTP",
        "severity": "HIGH", "cvss": "7.4",
        "cwe": "CWE-319", "owasp": "A02:2021",
        "verified_exploit": True,  # observed http:// scheme on the login URL/form action
        "evidence": ("The login endpoint is served (or its form action posts) over "
                     "plain HTTP, so submitted usernames and passwords traverse the "
                     f"network unencrypted. {hits[0].get('detail','')}"),
        "remediation": ("Serve the entire authentication flow over HTTPS only. "
                        "Redirect HTTP->HTTPS (301), set HSTS "
                        "(Strict-Transport-Security: max-age>=31536000; "
                        "includeSubDomains; preload), and ensure the form action "
                        "uses an https:// (or scheme-relative) URL."),
    }


def rule_session_cookie_insecure(s):
    hits = _kinds(s, "cookie_missing_secure", "cookie_missing_httponly")
    if not hits:
        return None
    flags = ", ".join(sorted({h.get("detail", "") for h in hits if h.get("detail")}))
    return {
        "name": "Session/auth cookie missing Secure or HttpOnly flag",
        "severity": "MEDIUM", "cvss": "5.4",
        "cwe": "CWE-1004", "owasp": "A05:2021",
        "verified_exploit": True,  # flags read directly from Set-Cookie header
        "evidence": ("A cookie set on the authentication surface is missing a "
                     "hardening flag observed directly in the Set-Cookie header: "
                     f"{flags}. Missing Secure allows transmission over HTTP; "
                     "missing HttpOnly exposes the cookie to XSS-based theft, "
                     "both of which assist session/credential compromise."),
        "remediation": ("Set Secure + HttpOnly on all session/auth cookies and add "
                        "SameSite=Lax or Strict. Secure prevents the cookie leaking "
                        "over HTTP; HttpOnly blocks JavaScript access."),
    }


def rule_password_autocomplete(s):
    hits = _kinds(s, "password_autocomplete_on")
    if not hits:
        return None
    return {
        "name": "Password field allows browser autocomplete on shared/login form",
        "severity": "LOW", "cvss": "3.1",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "verified_exploit": True,  # attribute read from actual form HTML
        "evidence": ("The password input does not disable autocomplete "
                     "(no autocomplete=off / current-password handling observed in "
                     "the form HTML). On shared or kiosk machines this can leave "
                     "credentials cached in the browser."),
        "remediation": ("For high-assurance flows set autocomplete=\"off\" on the "
                        "form or autocomplete=\"current-password\" on the password "
                        "input. Note: modern password managers intentionally "
                        "ignore autocomplete=off, so treat this as defence-in-depth "
                        "for shared-device scenarios, not a primary control."),
    }


def rule_no_clickjack_protection(s):
    hits = _kinds(s, "login_framable")
    if not hits:
        return None
    return {
        "name": "Login page can be framed (no X-Frame-Options / frame-ancestors)",
        "severity": "MEDIUM", "cvss": "4.3",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "verified_exploit": True,  # headers absent on the actual login response
        "evidence": ("The login response sets neither X-Frame-Options nor a CSP "
                     "frame-ancestors directive, so the page can be embedded in an "
                     "attacker-controlled iframe. This enables clickjacking / "
                     "login-overlay credential-harvesting attacks."),
        "remediation": ("Set Content-Security-Policy: frame-ancestors 'none' (or "
                        "'self') on the login page, and X-Frame-Options: DENY for "
                        "legacy browsers."),
    }


def rule_antiautomation_advisory(s):
    """Rate-limiting / lockout / CAPTCHA presence cannot be safely PROVEN
    from an external SaaS without actually hammering the login form (which
    we will not do). Report the assessment as advisory INFO, never as a
    graded finding — preserves the zero-FP contract."""
    if not s.get("login_form_detected"):
        return None
    observed = s.get("antiautomation_signals") or {}
    return {
        "name": "[ADVISORY-BY-DESIGN] Credential-stuffing rate-limit / lockout assessment",
        "severity": "INFO",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "evidence": ("A login form was detected. Whether the form enforces rate "
                     "limiting, account lockout, or CAPTCHA cannot be confirmed "
                     "without submitting many failed logins, which this scanner "
                     "intentionally does NOT do (detection-only, no brute force). "
                     f"Passive signals observed: {observed or 'none'}."),
        "remediation": ("Verify in the application that the login endpoint enforces: "
                        "(1) per-account + per-IP rate limiting, (2) progressive "
                        "lockout or delay after N failures, (3) CAPTCHA / proof-of-"
                        "work after threshold, (4) generic error messages (no user "
                        "enumeration), and (5) breached-password rejection (NIST "
                        "800-63B). Use a dedicated authenticated test to confirm."),
    }


def rule_positive_clean(s):
    if (s.get("methodology_total") or 0) > 0:
        return None
    if not s.get("login_form_detected"):
        return None
    return {
        "name": "Login surface hardening checks passed",
        "severity": "POSITIVE",
        "evidence": ("The detected login form is served over HTTPS, its cookies "
                     "carry Secure+HttpOnly, the page is frame-protected, and the "
                     "password field is configured appropriately. No transport or "
                     "client-side hardening gaps were observed."),
        "remediation": ("Maintain — pair these client-side controls with "
                        "server-side rate limiting, account lockout, MFA, and "
                        "breached-password rejection (NIST 800-63B)."),
        "cwe": "CWE-307",
        "owasp": "A07:2021",
    }


LOGIN_HARDENING_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_target_unreachable,
    rule_positive_clean,
    rule_login_over_http,
    rule_session_cookie_insecure,
    rule_password_autocomplete,
    rule_no_clickjack_protection,
    rule_antiautomation_advisory,
]
