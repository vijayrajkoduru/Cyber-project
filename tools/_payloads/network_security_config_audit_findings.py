"""network_security_config_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("network_security_config_audit_total"):
        return None
    return {"name": "Network Security Config: no cleartext / user-CA issues",
            "severity": "POSITIVE",
            "evidence": "network_security_config.xml parsed cleanly OR absent (Android 9+ defaults secure)",
            "remediation": "Maintain current defaults.",
            "cwe": "CWE-319", "owasp": "M5:2023"}


def rule_cleartext_traffic(s):
    issues = [i for i in (s.get("nsc_issues") or []) if i.get("flag") == "cleartextTrafficPermitted"]
    if not issues:
        return None
    domains = []
    for i in issues:
        if i.get("scope") == "base-config":
            domains.append("(all domains)")
        else:
            domains.extend(i.get("domains") or [])
    return {"name": f"cleartextTrafficPermitted=true allows HTTP traffic",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": "Domains: " + ", ".join(d or "(any)" for d in domains[:8]),
            "remediation": "Set cleartextTrafficPermitted=false. Migrate all listed domains to HTTPS."}


def rule_user_trust_anchors(s):
    issues = [i for i in (s.get("nsc_issues") or []) if i.get("flag") == "user-trust-anchors"]
    if not issues:
        return None
    return {"name": "App trusts user-installed CA certificates",
            "severity": "MEDIUM", "cvss": "5.4",
            "cwe": "CWE-295", "owasp": "M5:2023",
            "evidence": "trust-anchors src='user' configured",
            "remediation": "Remove user-CA trust anchors from release builds. Users could install MITM CAs."}


NETWORK_SECURITY_CONFIG_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_cleartext_traffic,
    rule_user_trust_anchors,
]
