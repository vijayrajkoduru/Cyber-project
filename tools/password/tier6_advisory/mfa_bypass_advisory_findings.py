"""mfa_bypass_advisory - findings rules (advisory-by-design).

A single INFO finding. §8 modern-auth BYPASS EXECUTION (MFA fatigue / OTP
brute / SIM swap / EvilGinx phishing) are ACTIVE attacks against users,
carriers, and live auth flows - out of scope for a detection-only (VA, not
PT) scanner. The POSTURE side (MFA / WebAuthn / passkey presence) IS probed
live by mfa_passkey_surface_audit. NEVER graded: always INFO.
"""


def rule_advisory(s):
    if not s.get("advisory"):
        return None
    title = s.get("advisory_title") or ""
    return {
        "name": f"[ADVISORY-BY-DESIGN] {title}",
        "severity": "INFO",
        "evidence": s.get("advisory_reason") or "",
        "remediation": (
            "This technique cannot be SaaS-probed and is intentionally advisory "
            "(NOT a forge gap). These execution techniques require explicit "
            "engagement authorization and manual / social-engineering / red-team "
            "execution. The POSTURE side is covered by mfa_passkey_surface_audit. "
            "See module_playbooks/08_password.md §8."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-308",
        "owasp": "N/A",
    }


MFA_BYPASS_ADVISORY_FINDING_RULES = [rule_advisory]
