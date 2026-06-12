"""ad_kerberos_userenum - findings rules (Kerberos username enumeration, §3 #40).

ZERO-FALSE-POSITIVE contract:
  - A username is reported VALID only when the KDC returned
    KRB5KDC_ERR_PREAUTH_REQUIRED (proves the principal exists). Unknown
    principals (KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) are NOT reported as valid.
  - This is enumeration (which names exist), not authentication — no password
    is ever sent, so a valid username is a MEDIUM info-disclosure surface, not
    a compromise. Lockout is never risked (pre-auth-less AS-REQ does not count
    as a logon failure).
"""


def rule_binary_missing(s):
    if s.get("ad_kuserenum_error") != "impacket not installed":
        return None
    return {"name": "Kerberos user-enum skipped - impacket not installed",
            "severity": "INFO",
            "evidence": "impacket Kerberos modules unavailable in scan image",
            "remediation": "Install impacket in the scan image (pip install impacket).",
            "cwe": "CWE-1006"}


def rule_input_missing(s):
    if not s.get("ad_kuserenum_input_missing"):
        return None
    return {"name": "Kerberos user-enum skipped - input required",
            "severity": "INFO",
            "evidence": "options.domain + options.userlist were not provided",
            "remediation": ("Provide options.domain (AD FQDN) + options.userlist "
                            "(candidate usernames, max 300). The probe sends a pre-auth-less "
                            "AS-REQ per name and classifies each by the KDC error code "
                            "(exists vs unknown). No password is sent; no lockout risk."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("ad_kuserenum_error") or s.get("ad_kuserenum_input_missing"):
        return None
    tested = s.get("ad_kuserenum_tested", 0)
    if tested == 0:
        return None
    if s.get("ad_kuserenum_valid"):
        return None
    return {"name": f"Kerberos username enumeration found no valid names ({tested} tried)",
            "severity": "POSITIVE",
            "evidence": f"{tested} candidate name(s) tried; KDC confirmed none.",
            "remediation": "No action — none of the supplied candidate usernames exist.",
            "cwe": "CWE-204", "owasp": "A01:2021"}


def rule_valid_users(s):
    valid = s.get("ad_kuserenum_valid") or []
    if not valid:
        return None
    sample = ", ".join(str(u) for u in valid[:10])
    return {"name": f"Valid domain usernames confirmed via Kerberos ({len(valid)})",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-204", "owasp": "A01:2021",
            "evidence": (f"KDC returned KRB5KDC_ERR_PREAUTH_REQUIRED (principal exists) for: "
                         f"{sample}. The KDC discloses valid vs invalid usernames pre-auth, "
                         f"giving an attacker a confirmed target list for spray / roast."),
            "remediation": ("Username enumeration via Kerberos is inherent to the protocol and "
                            "cannot be fully disabled, so compensate: enforce account lockout / "
                            "smart lockout, strong unique passwords, and MFA so a confirmed "
                            "username list yields no usable credential. Avoid predictable naming "
                            "(first.last) for privileged/service accounts. Monitor event 4768 "
                            "for high-volume pre-auth failures from one source.")}


AD_KERBEROS_USERENUM_FINDING_RULES = [rule_binary_missing, rule_input_missing,
                                      rule_positive, rule_valid_users]
