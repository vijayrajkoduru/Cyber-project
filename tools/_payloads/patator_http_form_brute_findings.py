"""patator_http_form_brute - findings rules."""


def rule_critical_login(s):
    succ = s.get("patator_http_form_successes") or []
    if not succ:
        return None
    user_list = ", ".join(sorted({x.get("user", "?") for x in succ}))[:200]
    return {
        "name": f"Weak web-form password proven - {len(succ)} valid credential(s) on {s.get('patator_http_form_url', 'login form')}",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (f"Patator http_fuzz succeeded against user(s): {user_list}. "
                     f"{s.get('patator_http_form_brute_attempts', 0)} total attempts. "
                     "(Passwords redacted per VulnusLab privacy policy.)"),
        "remediation": (
            "1. Force-reset the password for every affected account and review the application's audit log for unauthorized session activity. "
            "2. Implement application-level lockout (5 fails -> 15 min cooldown) and add a CAPTCHA after 3 fails. "
            "3. Enforce minimum 12-char passphrases at signup + on password reset; reject the top-1000 breach corpus via HIBP Pwned Passwords API. "
            "4. Add TOTP / WebAuthn / Passkey as a mandatory second factor for all human accounts. "
            "5. Add WAF rule against fast repeated POSTs to the login endpoint (Cloudflare Rate Limiting / AWS WAF managed Rule)."
        ),
    }


def rule_input_missing(s):
    missing = s.get("patator_input_missing") or []
    if not missing:
        return None
    return {
        "name": "Patator HTTP form brute skipped - required options not supplied",
        "severity": "INFO",
        "evidence": (f"Missing options: {', '.join(missing)}. This scanner needs all of: "
                     "form_url, user_field, pass_field, fail_string, userlist, passlist."),
        "remediation": (
            "Re-run with all six options populated. fail_string should be a phrase that appears "
            "ONLY in the failure response (e.g. 'Invalid email or password'). Inspect a wrong-login response in your browser DevTools to pick the right string."
        ),
        "cwe": "CWE-1006",
    }


def rule_invalid_form_url(s):
    if not s.get("patator_form_url_invalid"):
        return None
    return {
        "name": "Patator HTTP form brute skipped - invalid form_url",
        "severity": "INFO",
        "evidence": "options.form_url must be a full http(s):// URL including hostname.",
        "remediation": "Pass form_url as e.g. https://app.example.com/api/login (the POST endpoint).",
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("patator_http_form_brute_error"):
        return None
    if "patator binary not installed" not in str(s.get("patator_http_form_brute_error")):
        return None
    return {
        "name": "Patator binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('patator') returned None.",
        "remediation": "Install patator: apt install patator (Debian/Kali) or pip install patator.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("patator_http_form_brute_total"):
        return None
    if s.get("patator_input_missing"):
        return None
    if s.get("patator_form_url_invalid"):
        return None
    if s.get("patator_http_form_brute_error"):
        return None
    attempts = s.get("patator_http_form_brute_attempts") or 0
    if not attempts:
        return None
    return {
        "name": "Web form withstood Patator password spray",
        "severity": "POSITIVE",
        "evidence": (f"{attempts} attempt(s) over "
                     f"{s.get('patator_http_form_users_tried', 0)} user(s) on "
                     f"{s.get('patator_http_form_url', 'login form')} - no valid login."),
        "remediation": ("Maintain CAPTCHA + rate-limit + HIBP check at signup. "
                        "Re-spray quarterly with fresh breach corpus."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


PATATOR_HTTP_FORM_BRUTE_FINDING_RULES = [
    rule_critical_login,
    rule_input_missing,
    rule_invalid_form_url,
    rule_binary_missing,
    rule_positive,
]
