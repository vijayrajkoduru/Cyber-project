"""ad_smb_null_session - findings rules (null-session RPC/SMB, playbook §1 #6).

ZERO-FALSE-POSITIVE contract:
  - HIGH (null session) is emitted ONLY when an anonymous (null) SMB login
    actually succeeded against the live target.
  - The leaked-shares finding is emitted ONLY when shares were actually listed
    over that null session.
"""


def rule_positive(s):
    if s.get("ad_nullsess_error") or s.get("ad_nullsess_unreachable"):
        return None
    if not s.get("ad_nullsess_probed"):
        return None
    if s.get("ad_nullsess_allowed"):
        return None
    return {"name": "Null SMB session rejected by target",
            "severity": "POSITIVE",
            "evidence": "Anonymous (null) SMB login was refused — RestrictAnonymous enforced.",
            "remediation": "Continue blocking anonymous SMB sessions (RestrictAnonymous=2).",
            "cwe": "CWE-287", "owasp": "A07:2021"}


def rule_null_session(s):
    if not s.get("ad_nullsess_allowed"):
        return None
    return {"name": "Anonymous (null) SMB session accepted",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-287", "owasp": "A07:2021",
            "evidence": ("Target accepted an anonymous SMB login (empty username + password). "
                         "This permits credential-less RPC/SMB enumeration of the host."),
            "remediation": ("Restrict anonymous access via GPO: 'Network access: Restrict "
                            "anonymous access to Named Pipes and Shares' = Enabled, "
                            "'Network access: Do not allow anonymous enumeration of SAM "
                            "accounts and shares' = Enabled, and set RestrictAnonymous=2 on "
                            "every DC + member server.")}


def rule_shares_leaked(s):
    shares = s.get("ad_nullsess_shares") or []
    if not shares:
        return None
    names = ", ".join(str(x) for x in shares[:10])
    return {"name": f"SMB shares enumerated over null session ({len(shares)})",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": f"Shares listed without credentials: {names}",
            "remediation": ("An unauthenticated attacker can map the host's shares (and often "
                            "browse readable ones). Disable null-session share enumeration "
                            "(rule above) and audit share ACLs — remove ANONYMOUS LOGON / "
                            "Everyone read where not required.")}


AD_SMB_NULL_SESSION_FINDING_RULES = [rule_positive, rule_null_session, rule_shares_leaked]
