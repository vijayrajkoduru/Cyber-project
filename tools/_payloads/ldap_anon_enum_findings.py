"""ldap_anon_enum - findings rules."""


def rule_positive(s):
    if s.get("ldap_anon_enum_total"):
        return None
    if s.get("ldap_unreachable"):
        return None
    return {"name": "Anonymous LDAP bind rejected",
            "severity": "POSITIVE",
            "evidence": "DC refused anonymous bind on port 389",
            "remediation": "Continue requiring authenticated LDAP binds.",
            "cwe": "CWE-287", "owasp": "A07:2021"}


def rule_anonymous_bind_allowed(s):
    f = s.get("ldap_anon_findings") or []
    if not any(x.get("check") == "anonymous_bind_allowed" for x in f):
        return None
    return {"name": "Anonymous LDAP bind allowed on Domain Controller",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-287", "owasp": "A07:2021",
            "evidence": "ldap3 anonymous bind to port 389 succeeded — no creds required",
            "remediation": ("Disable anonymous bind on the DC. In ADSI Edit: "
                            "Configuration > Services > Windows NT > Directory Service "
                            "set 'dsHeuristics' attribute 7th character to '0'. "
                            "Verify via: Get-ADRootDSE.")}


def rule_root_dse_readable(s):
    rd = s.get("root_dse") or {}
    if not rd.get("naming_contexts"):
        return None
    return {"name": "Root DSE leaks naming contexts anonymously",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": "Anonymous read returned naming contexts: " +
                        ", ".join(rd["naming_contexts"][:3]),
            "remediation": ("Restrict pre-bind LDAP queries — root DSE should still be "
                            "readable per RFC but the domain naming context should not. "
                            "Audit dsHeuristics + LDAP query policy.")}


def rule_base_dn_anonymous_read(s):
    f = s.get("ldap_anon_findings") or []
    if not any(x.get("check") == "base_dn_anonymous_read" for x in f):
        return None
    return {"name": "Base DN entries readable anonymously",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": "Anonymous LDAP read of base naming context returned data",
            "remediation": ("Critical — pre-auth attacker can map your AD structure. "
                            "Set dsHeuristics flag 0007 to disable anonymous queries.")}


LDAP_ANON_ENUM_FINDING_RULES = [rule_positive, rule_anonymous_bind_allowed,
                                  rule_root_dse_readable, rule_base_dn_anonymous_read]
