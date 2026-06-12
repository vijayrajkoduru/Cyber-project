"""mfa_passkey_surface_audit - finding rules (VL-METHOD aware).

Reads state populated by MfaPasskeySurfaceAudit:
  - methodology_findings : list of MFA/passkey surface observations
  - mfa_indicators       : dict of passively-detected MFA/WebAuthn markers
  - target_base          : normalized base URL
  - login_form_detected  : bool

ZERO-FALSE-POSITIVE CONTRACT
----------------------------
This scanner reports MFA / passkey POSTURE. Almost every output is
informational by design — the presence or absence of MFA on a login page
is an observation, not a vulnerability we can exploit from outside.

The one graded finding (otp_endpoint_no_throttle_headers) is emitted ONLY
when an OTP/verification endpoint is reachable AND returns no documented
throttling headers — and even then it is capped at LOW, because confirming
exploitability would require active OTP brute (which this scanner refuses
to do). Everything else is INFO / advisory-by-design.
"""


INTEL_FIELDS = [
    ("Target",              "target_base"),
    ("Login form detected", "login_form_detected"),
    ("MFA indicators",      "mfa_indicators"),
    ("WebAuthn endpoints",  "webauthn_endpoints"),
    ("OTP endpoints",       "otp_endpoints"),
    ("Stage timings (ms)",  "stage_timings"),
    ("Stage errors",        "stage_errors"),
]


def _kinds(s, *want):
    return [f for f in (s.get("methodology_findings") or []) if f.get("kind") in want]


def rule_input_missing(s):
    sr = s.get("skipped_reason") or ""
    if "no target" not in sr:
        return None
    return {
        "name": "No target supplied - MFA/passkey surface audit skipped",
        "severity": "INFO",
        "evidence": sr,
        "remediation": "Supply the application base URL on the request body.",
        "cwe": "CWE-1006",
    }


def rule_unreachable(s):
    sr = s.get("skipped_reason") or ""
    if "not reachable" not in sr:
        return None
    return {
        "name": "Target HTTP endpoint not reachable - MFA surface not assessed",
        "severity": "INFO",
        "evidence": sr,
        "remediation": ("Confirm the application is reachable and re-run so the "
                        "MFA / passkey surface can be enumerated."),
        "cwe": "CWE-1006",
    }


def rule_webauthn_supported(s):
    hits = _kinds(s, "webauthn_supported")
    if not hits:
        return None
    where = ", ".join(sorted({h.get("detail", "") for h in hits if h.get("detail")}))
    return {
        "name": "WebAuthn / passkey support detected (phishing-resistant MFA available)",
        "severity": "POSITIVE",
        "evidence": ("The application exposes WebAuthn / FIDO2 passkey endpoints "
                     f"or client markers ({where}). Passkeys are phishing-resistant "
                     "and resist credential stuffing, password spray, and MFA "
                     "fatigue. This is a positive security posture."),
        "remediation": ("Maintain — encourage or require passkey enrollment, and "
                        "ensure no weaker fallback (SMS OTP, security questions) "
                        "silently downgrades the phishing-resistance guarantee."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
    }


def rule_mfa_offered(s):
    hits = _kinds(s, "mfa_offered")
    if not hits:
        return None
    where = ", ".join(sorted({h.get("detail", "") for h in hits if h.get("detail")}))
    return {
        "name": "[ADVISORY-BY-DESIGN] Multi-factor authentication surface detected",
        "severity": "INFO",
        "evidence": ("MFA-related endpoints / markers were observed "
                     f"({where}). Whether MFA is ENFORCED for all accounts (vs "
                     "optional) cannot be determined externally without "
                     "authenticated testing. This is an informational observation, "
                     "not a finding."),
        "remediation": ("Verify MFA is mandatory for all privileged accounts and "
                        "that recovery / fallback flows (SMS, email OTP, backup "
                        "codes) cannot be abused to bypass the stronger factor "
                        "(MFA-fatigue / OTP-brute / SIM-swap resistance)."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
    }


def rule_no_mfa_detected(s):
    if not s.get("login_form_detected"):
        return None
    # Only emit when a login form exists but NO MFA/passkey markers were seen.
    # A reachable OTP/verification endpoint is itself an MFA marker, so its
    # presence also suppresses this "no MFA observed" advisory.
    if _kinds(s, "mfa_offered", "webauthn_supported", "otp_endpoint_no_throttle"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] No MFA / passkey markers observed on the authentication surface",
        "severity": "INFO",
        "evidence": ("A login form was detected but no WebAuthn / passkey / OTP / "
                     "TOTP markers were observed in the public authentication "
                     "surface. Absence of markers does NOT prove MFA is disabled "
                     "(MFA may be enforced only after the first factor), so this is "
                     "advisory only — not a graded finding."),
        "remediation": ("Confirm MFA is available and enforced. NIST SP 800-63B and "
                        "OWASP ASVS V2 require phishing-resistant MFA for "
                        "high-assurance flows. Prefer passkeys / FIDO2 over SMS OTP."),
        "cwe": "CWE-308",
        "owasp": "A07:2021",
    }


def rule_otp_endpoint_exposed(s):
    """OTP/verification endpoint reachable without documented throttling
    headers. Capped at LOW: we OBSERVED the endpoint, but cannot prove it
    is brute-forceable without active OTP submission (which we do not do)."""
    hits = _kinds(s, "otp_endpoint_no_throttle")
    if not hits:
        return None
    where = ", ".join(sorted({h.get("detail", "") for h in hits if h.get("detail")}))
    return {
        "name": "OTP / verification endpoint reachable without throttling headers",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "verified_exploit": True,  # endpoint reachable + no RateLimit/Retry-After headers observed
        "evidence": ("A one-time-code / verification endpoint is reachable and its "
                     "responses carry no RateLimit-* / Retry-After throttling "
                     f"headers ({where}). If the endpoint also lacks server-side "
                     "attempt limiting, short numeric OTPs become brute-forceable. "
                     "This scan did NOT submit any codes — confirm throttling via a "
                     "dedicated authenticated test."),
        "remediation": ("Enforce strict per-account + per-IP rate limiting and a "
                        "hard attempt cap (e.g. 5 tries) on OTP verification, with "
                        "exponential backoff and code expiry <= 5 minutes. Surface "
                        "RateLimit-* headers. Prefer push-with-number-matching or "
                        "passkeys over short numeric OTP."),
    }


MFA_PASSKEY_SURFACE_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_unreachable,
    rule_webauthn_supported,
    rule_mfa_offered,
    rule_no_mfa_detected,
    rule_otp_endpoint_exposed,
]
