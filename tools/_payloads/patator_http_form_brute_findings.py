"""patator_http_form_brute - finding rules (VL-METHOD aware).

REWRITTEN 2026-06-05 for the VL-METHOD methodology pattern. Reads new
state keys populated by PatatorHttpFormBrute's 7-stage flow:
  - methodology_findings  : list of verified credentials
  - skipped_reason        : str from pre_flight (if unreachable)
  - fingerprint           : dict {server, framework, captcha_detected,
                                   rate_limit_headers, form_action, ...}
  - captcha_detected      : bool shortcut from fingerprint
  - chain_next            : list of follow-up scanner names
  - patator_input_missing : list of missing required options
  - patator_missing       : bool (patator binary not installed)

Severity matrix:
  CONFIRMED admin      -> CRITICAL  CVSS 9.8   (admin panel access via web)
  CONFIRMED user       -> HIGH      CVSS 7.5   (user account takeover via web)
  CONFIRMED guest      -> LOW       CVSS 4.3
  SUSPECTED any        -> LOW       CVSS 3.7   (manual confirm needed)
"""


def _findings_by_severity(s):
    """Bucket methodology_findings by severity computed from
    confidence + privilege_level."""
    out = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":
                out["CRITICAL"].append(f)
            elif priv == "user":
                out["HIGH"].append(f)
            elif priv == "guest":
                out["LOW"].append(f)
            else:
                # unknown but CONFIRMED login -> treat as HIGH (account
                # takeover is HIGH regardless of admin-section presence)
                out["HIGH"].append(f)
        else:
            out["LOW"].append(f)
    return out


def rule_form_url_unreachable(s):
    """Pre-flight failed - either form_url missing or HTTP probe failed."""
    reason = (s.get("skipped_reason") or "")
    if not reason:
        return None
    # Don't fire for "input missing" cases - rule_input_missing handles those
    if "form_url not supplied" in reason:
        return {
            "name": "Patator HTTP form brute skipped - form_url not supplied",
            "severity": "INFO",
            "evidence": ("This scanner requires options.form_url - the full POST URL of "
                         "the login form, e.g. https://app.example.com/login. "
                         "Without it the scanner cannot reach the login endpoint."),
            "remediation": ("Re-run with options.form_url set. Inspect the login page in "
                            "browser DevTools (Network tab) on a failed login attempt - "
                            "the Request URL of the POST is what to paste."),
            "cwe": "CWE-1006",
        }
    if "invalid form_url" in reason or s.get("patator_form_url_invalid"):
        return {
            "name": "Patator HTTP form brute skipped - invalid form_url",
            "severity": "INFO",
            "evidence": f"options.form_url must be a full http(s):// URL: {reason}",
            "remediation": "Pass form_url as e.g. https://app.example.com/api/login (the POST endpoint).",
            "cwe": "CWE-1006",
        }
    return {
        "name": "Login form unreachable - cannot test password security",
        "severity": "INFO",
        "evidence": reason,
        "remediation": ("If the login URL is correct, verify the app is online and the "
                        "scanner host can reach it (no firewall / IP allowlist blocking). "
                        "Re-run scan once the form is reachable to actually test "
                        "credential strength."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    """Deep_scan was skipped because customer didn't supply userlist+passlist
    +fail_string. Quick-probe still ran 5 admin defaults."""
    missing = s.get("patator_input_missing") or []
    deep_skipped = s.get("deep_skipped") or ""
    if not missing and "required options missing" not in deep_skipped:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        # Quick-probe found something - don't dilute the report with INFO
        return None
    miss_str = ", ".join(missing) if missing else deep_skipped
    return {
        "name": "Deep brute skipped - userlist/passlist/fail_string not provided",
        "severity": "INFO",
        "evidence": (f"Missing options: {miss_str}. Quick-probe ran 5 admin defaults "
                     f"(admin/admin, admin/password, admin/123456, root/root, "
                     f"administrator/blank) - none worked. To run a full spray, "
                     f"supply options.userlist + options.passlist + options.fail_string."),
        "remediation": ("Supply all three options. fail_string should be a phrase that "
                        "appears ONLY in the failure response (e.g. 'Invalid email or "
                        "password'). Inspect a wrong-login response in browser DevTools "
                        "to pick the right string. Max 10 users x 25 passwords per run."),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    """Patator binary missing on the scanner host."""
    if not s.get("patator_missing"):
        return None
    return {
        "name": "Patator binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('patator') returned None. Deep_scan cannot run.",
        "remediation": "Install patator: apt install patator (Debian/Kali) or pip install patator.",
        "cwe": "CWE-1006",
    }


def rule_captcha_detected(s):
    """Login form is CAPTCHA-protected and we found no valid logins -
    that's a POSITIVE finding for the customer (good hardening)."""
    fp = s.get("fingerprint") or {}
    if not fp.get("captcha_detected"):
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        # CAPTCHA was bypassed somehow (or admin defaults work) - not positive
        return None
    return {
        "name": "Login form protected by CAPTCHA - automated spray rejected",
        "severity": "POSITIVE",
        "evidence": (f"CAPTCHA detected on {s.get('form_url', 'login form')} "
                     f"(framework: {fp.get('framework', 'unknown')}). "
                     "Deep_scan was skipped to avoid triggering anti-bot detection. "
                     "Manual testing required to assess credential strength."),
        "remediation": ("Keep the CAPTCHA in place. Consider invisible reCAPTCHA v3 or "
                        "hCaptcha for better UX. Re-test quarterly to ensure CAPTCHA "
                        "isn't accidentally disabled by an A/B test or config rollback."),
        "cwe": "CWE-307",
        "owasp": "A07:2021",
    }


def rule_rate_limit_detected(s):
    """Rate-limit headers present and no logins found - good security."""
    fp = s.get("fingerprint") or {}
    rl = fp.get("rate_limit_headers") or {}
    if not rl:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        return None
    return {
        "name": "Login endpoint advertises rate limiting - brute-force paused",
        "severity": "POSITIVE",
        "evidence": (f"Rate-limit headers detected on {s.get('form_url', 'login form')}: "
                     f"{rl}. Deep_scan was paused to avoid tripping the limit (which "
                     "would skew results + alert the SOC)."),
        "remediation": ("Maintain rate limiting. Recommended: 5 failed attempts -> 15 min "
                        "lockout per IP + per account. Pair with X-RateLimit-* response "
                        "headers (already in place here) so legitimate clients can back off."),
        "cwe": "CWE-307",
        "owasp": "A07:2021",
    }


def rule_positive_no_defaults(s):
    """Quick-probe ran, no hits, no real findings - GOOD signal."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if s.get("skipped_reason"):
        return None
    # Don't duplicate POSITIVE messaging with captcha/rate-limit rules
    fp = s.get("fingerprint") or {}
    if fp.get("captcha_detected") or fp.get("rate_limit_headers"):
        return None
    return {
        "name": "Login form rejects all 5 admin default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} admin defaults "
                     "(admin/admin, admin/password, admin/123456, root/root, "
                     f"administrator/blank) on {s.get('form_url', 'login form')}; "
                     f"all rejected. Server: {fp.get('server', 'unknown')}, "
                     f"Framework: {fp.get('framework', 'unknown')}."),
        "remediation": ("Continue rejecting default credentials. Add CAPTCHA after 3 "
                        "fails, enforce 12+ char passphrases at signup, reject HIBP "
                        "Pwned Passwords top-1000 corpus. Make TOTP/WebAuthn mandatory "
                        "for any admin-grade account."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_confirmed_admin(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["CRITICAL"]}))[:200]
    return {
        "name": f"CONFIRMED admin web-login via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (f"Admin-grade account(s) compromised via login form spray on "
                     f"{s.get('form_url', 'login form')}. Verified by httpx re-POST "
                     f"with session-cookie detection, then admin-path GET returned 200 "
                     f"(verification_method=httpx_session_cookie_detected). "
                     f"Compromised users: {users}. (Passwords redacted.)"),
        "remediation": ("CRITICAL - rotate passwords for the compromised admin accounts "
                        "immediately and review application audit logs for unauthorized "
                        "session activity. Enforce: (1) 12+ char passphrases + HIBP "
                        "breach-corpus check at signup, (2) mandatory TOTP/WebAuthn for "
                        "admin accounts, (3) application-level lockout (5 fails -> 15 "
                        "min cooldown) + CAPTCHA after 3 fails, (4) WAF rate-limit rule "
                        "on /login (Cloudflare Rate Limiting / AWS WAF managed Rule). "
                        "Consider the admin panel compromised until proven clean."),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["HIGH"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["HIGH"]}))[:200]
    return {
        "name": f"CONFIRMED user web-login via password ({len(g['HIGH'])} account)",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (f"Regular user account(s) compromised via login form spray on "
                     f"{s.get('form_url', 'login form')}. Verified by httpx re-POST + "
                     "session-cookie detection (no admin section reachable, or admin "
                     f"probe returned 403). Compromised users: {users}. "
                     "(Passwords redacted.)"),
        "remediation": ("Force password reset on the affected accounts and notify the "
                        "account owners. Enforce password complexity (12+ chars, HIBP "
                        "check) + offer/require TOTP. Add application-level lockout (5 "
                        "fails -> 15 min) and CAPTCHA after 3 fails to slow future "
                        "credential-stuffing campaigns."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    confirmed_low = [f for f in g["LOW"] if f.get("confidence") == "CONFIRMED"]
    if not confirmed_low:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in confirmed_low}))[:200]
    return {
        "name": f"CONFIRMED guest/low-priv web-login via password ({len(confirmed_low)} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (f"Guest-level account(s) compromised: {users}. Limited impact "
                     "(read-only / sandboxed account)."),
        "remediation": ("Even guest accounts should not use trivial passwords - they "
                        "can be used as a foothold for further enumeration. Rotate the "
                        "affected passwords and enforce minimum-strength policy."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in suspected[:5]}))[:200]
    return {
        "name": f"SUSPECTED web-form credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Patator reported these credentials as valid but the verification "
                     "re-POST could not confirm a session cookie or redirect-to-app. "
                     "Could be a Patator false-positive (transient 200 OK) OR an account "
                     "with login-but-no-session (e.g. step-up MFA required). "
                     f"Users: {users}."),
        "remediation": ("Manually attempt login in a browser. If session DOES start, "
                        "treat as CONFIRMED HIGH/CRITICAL per privilege. If MFA is the "
                        "blocker, the password is still weak - rotate it and ensure MFA "
                        "remains enforced. If login truly fails, mark scan finding as "
                        "false-positive and tune fail_string."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed web credentials enable downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically follow "
                        "up with: " + ", ".join(chain_next) + ". These will inherit the "
                        "captured session via the VL-METHOD chaining engine."),
        "cwe": "CWE-1006",
    }


PATATOR_HTTP_FORM_BRUTE_FINDING_RULES = [
    rule_form_url_unreachable,
    rule_input_missing,
    rule_binary_missing,
    rule_captcha_detected,
    rule_rate_limit_detected,
    rule_positive_no_defaults,
    rule_confirmed_admin,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
