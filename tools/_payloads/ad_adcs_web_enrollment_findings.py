"""ad_adcs_web_enrollment - findings rules (ESC8 surface, playbook §6 #77).

ZERO-FALSE-POSITIVE contract:
  - The graded (MEDIUM) ESC8-relay-surface finding is emitted ONLY when the
    target actually served an AD CS Web Enrollment endpoint (/certsrv) that
    answered with an NTLM/Negotiate challenge over cleartext HTTP. That is a
    DETECTED relay surface, not a planned one.
  - The actual ESC8 *exploit* (coerce + relay to /certsrv) is never performed
    (VA-not-PT). Confirming the cert template is enrollable still needs creds
    -> that part stays INFO advisory.
"""


def rule_positive(s):
    if s.get("ad_adcs_web_error"):
        return None
    probed = s.get("ad_adcs_web_endpoints") or []
    if not probed:
        return None
    if s.get("ad_adcs_esc8_surface"):
        return None
    return {"name": "AD CS Web Enrollment not exposed over cleartext HTTP",
            "severity": "POSITIVE",
            "evidence": f"Probed {len(probed)} certsrv path(s); no HTTP-NTLM relay surface found.",
            "remediation": "Keep /certsrv off plain HTTP (or fully disabled) to deny ESC8 relay.",
            "cwe": "CWE-295", "owasp": "A02:2021"}


def rule_esc8_http_surface(s):
    surf = s.get("ad_adcs_esc8_surface") or []
    if not surf:
        return None
    sample = "; ".join(f"{x.get('url')} -> {x.get('auth')}" for x in surf[:3])
    return {"name": "AD CS Web Enrollment (ESC8) reachable over cleartext HTTP with NTLM auth",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-295", "owasp": "A02:2021",
            "evidence": (f"Detected HTTP NTLM/Negotiate challenge on certsrv: {sample}. "
                         f"This is the ESC8 relay target (coerce DC -> relay to /certsrv "
                         f"-> obtain DC certificate)."),
            "remediation": ("Disable HTTP-based certificate enrollment, OR require HTTPS + "
                            "Extended Protection for Authentication (EPA) and enable channel "
                            "binding on the CA's web enrollment site. Also enforce SMB signing "
                            "and patch coercion vectors (PetitPotam/DFSCoerce) so an attacker "
                            "cannot relay machine auth to this endpoint.")}


def rule_https_only(s):
    surf = s.get("ad_adcs_https_endpoints") or []
    if not surf or s.get("ad_adcs_esc8_surface"):
        return None
    return {"name": "AD CS Web Enrollment present (HTTPS only)",
            "severity": "INFO",
            "evidence": "certsrv answered over HTTPS only: " +
                        ", ".join(x.get("url", "") for x in surf[:3]),
            "remediation": ("[ADVISORY] HTTPS enrollment is far safer than HTTP, but ESC8 can "
                            "still apply if EPA/channel-binding is not enforced. Confirming the "
                            "actual cert-template enrollability and EPA state requires domain "
                            "credentials (run certipy_find with creds)."),
            "cwe": "CWE-200", "owasp": "A02:2021"}


AD_ADCS_WEB_ENROLLMENT_FINDING_RULES = [rule_positive, rule_esc8_http_surface, rule_https_only]
