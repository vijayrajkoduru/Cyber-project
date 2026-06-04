"""mfa_bypass_test - findings rules.

Severity model:
  CRITICAL - any bypass mode succeeded (MFA gate is broken)
  HIGH     - protected_url returns authed content WITHOUT any login at all
  INFO     - missing input / httpx unavailable / replay test skipped
  POSITIVE - all 4 bypass attempts failed, MFA gate held
"""


def rule_critical_bypass(s):
    modes = s.get("mfa_bypass_modes") or []
    # Filter out the "unauth open" case (HIGH-level rule covers it cleaner)
    modes = [m for m in modes if m != "protected_url_unauth_open"]
    if not modes:
        return None
    detail_lines = []
    if s.get("mfa_skip_step_accepted"):
        detail_lines.append(
            f"skip_mfa_step: post-login session reached protected URL "
            f"(HTTP {s.get('mfa_skip_step_status')})"
        )
    forged = [r for r in (s.get("mfa_forged_cookie_results") or []) if r.get("accepted")]
    for f in forged:
        detail_lines.append(f"forged_cookie {f.get('flag')} -> HTTP {f.get('status')}")
    if s.get("mfa_replay_accepted"):
        detail_lines.append(
            f"replay of supplied MFA-success body succeeded "
            f"(MFA POST {s.get('mfa_replay_status')}, protected {s.get('mfa_replay_protected_status')})"
        )
    return {
        "name": f"MFA bypass succeeded via {len(modes)} mode(s): {', '.join(modes)}",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "evidence": (
            "The MFA gate was bypassed using the following modes: "
            f"{', '.join(modes)}. Detail: " + " | ".join(detail_lines) + ". "
            "Any of these means an attacker who steals only the password (phishing, breach corpus, "
            "shoulder-surf) can fully authenticate without ever satisfying the MFA challenge."
        ),
        "remediation": (
            "1. Enforce MFA SERVER-SIDE on every protected resource, not just on the post-login "
            "redirect. The check must be `if not session.mfa_verified: return 401`. "
            "2. Never store MFA state in a client-set cookie - store a server-side flag tied to "
            "the session record (Redis / DB column). "
            "3. Bind MFA verification to the originating session ID so a different session's "
            "MFA receipt cannot be replayed - record the session_id inside the MFA challenge token. "
            "4. Rotate the session ID after MFA completes (defence-in-depth vs fixation). "
            "5. Re-run this scan after the fix - any single succeeded bypass mode is a re-fix."
        ),
    }


def rule_high_unauth_open(s):
    if not s.get("mfa_protected_url_not_actually_protected"):
        return None
    return {
        "name": f"Protected URL returns authenticated content WITHOUT any login (status {s.get('mfa_unauth_baseline_status', '?')})",
        "severity": "HIGH",
        "cvss": "8.5",
        "cwe": "CWE-306",
        "owasp": "A01:2021",
        "evidence": (
            f"GET to the customer-supplied protected URL with NO cookies / NO Authorization "
            f"header returned status {s.get('mfa_unauth_baseline_status')} with a body that "
            "matched the authed-content heuristic. Either the resource isn't actually behind "
            "auth, or the auth check is performed client-side only (broken)."
        ),
        "remediation": (
            "1. Move the auth check to the server. Every protected route MUST validate "
            "session/JWT before returning data - never rely on client-side redirects. "
            "2. If this URL is intentionally public (mistake in options.protected_url), re-run "
            "with a different URL that genuinely requires MFA."
        ),
    }


def rule_input_missing(s):
    if not s.get("mfa_input_missing"):
        return None
    return {
        "name": "MFA bypass test skipped - missing required options",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe requires options.login_endpoint + options.mfa_endpoint + options.protected_url + "
            "options.test_username + options.test_password. Without all five no bypass attempts can run."
        ),
        "remediation": (
            "Re-run with all five populated. Optional: options.mfa_success_body (captured from a real "
            "MFA-pass POST via browser devtools) enables the replay test (c)."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("mfa_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to run the MFA bypass flow.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_replay_skipped(s):
    # Surface that the replay test didn't run so customers know to fill it in
    if not s.get("mfa_replay_skipped"):
        return None
    # Only show if no critical finding (avoid noise)
    if s.get("mfa_bypass_modes"):
        return None
    return {
        "name": "MFA replay test skipped - options.mfa_success_body not provided",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Tests (a), (b) and (d) ran. Test (c) — replaying a captured MFA-success body — was "
            "skipped because options.mfa_success_body was empty."
        ),
        "remediation": (
            "Capture the exact POST body sent to the MFA endpoint on a successful login via browser "
            "devtools / Burp, paste it into options.mfa_success_body (dict or raw form-encoded "
            "string), and re-run for full coverage."
        ),
    }


def rule_positive(s):
    if s.get("mfa_input_missing"):
        return None
    if s.get("mfa_httpx_missing"):
        return None
    if s.get("mfa_bypass_modes"):
        return None
    if s.get("mfa_protected_url_not_actually_protected"):
        return None
    return {
        "name": "MFA gate held against skip / cookie-forge / replay / unauth-baseline tests",
        "severity": "POSITIVE",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "evidence": (
            f"Skip-MFA-step status: {s.get('mfa_skip_step_status', '?')} (accepted={s.get('mfa_skip_step_accepted')}). "
            f"Replay accepted: {s.get('mfa_replay_accepted')}. "
            f"Unauth baseline status: {s.get('mfa_unauth_baseline_status', '?')}. "
            "None of the 4 bypass paths succeeded against the protected URL."
        ),
        "remediation": (
            "Keep the server-side MFA enforcement in place. Re-run after every auth-library upgrade "
            "(Auth0, Cognito, Azure AD) and after any change to the session middleware - "
            "regression bugs in this area are common."
        ),
    }


MFA_BYPASS_TEST_FINDING_RULES = [
    rule_critical_bypass,
    rule_high_unauth_open,
    rule_input_missing,
    rule_httpx_missing,
    rule_replay_skipped,
    rule_positive,
]
