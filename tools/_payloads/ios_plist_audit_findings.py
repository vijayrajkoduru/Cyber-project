"""ios_plist_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("ios_plist_audit_total"):
        return None
    return {"name": "iOS plist: no risky transport / entitlement flags",
            "severity": "POSITIVE",
            "evidence": "Info.plist + entitlements parsed cleanly",
            "remediation": "Maintain App Transport Security defaults.",
            "cwe": "CWE-319", "owasp": "M5:2023"}


def rule_arbitrary_loads(s):
    issues = [i for i in (s.get("plist_issues") or []) if i.get("flag") == "NSAllowsArbitraryLoads"]
    if not issues:
        return None
    return {"name": "App Transport Security disabled globally (NSAllowsArbitraryLoads=true)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": "; ".join(i["file"] for i in issues[:3]),
            "remediation": "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains for specific HTTP hosts if absolutely needed."}


def rule_exception_domains(s):
    issues = [i for i in (s.get("plist_issues") or []) if i.get("flag") == "NSExceptionAllowsInsecureHTTPLoads"]
    if not issues:
        return None
    return {"name": f"{len(issues)} domain(s) bypass TLS via ATS exceptions",
            "severity": "MEDIUM", "cvss": "5.4",
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": "; ".join(f"{i['file']}: {i.get('domain', '?')}" for i in issues[:5]),
            "remediation": "Migrate listed domains to HTTPS; remove their ATS exceptions."}


def rule_file_sharing(s):
    issues = [i for i in (s.get("plist_issues") or []) if i.get("flag") == "UIFileSharingEnabled"]
    if not issues:
        return None
    return {"name": "App exposes Documents folder via iTunes/Files (UIFileSharingEnabled=true)",
            "severity": "MEDIUM", "cvss": "4.3",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": "; ".join(i["file"] for i in issues[:3]),
            "remediation": "Remove UIFileSharingEnabled if app doesn't need user-visible file sharing."}


def rule_get_task_allow(s):
    issues = [i for i in (s.get("plist_issues") or []) if i.get("flag") == "get-task-allow"]
    if not issues:
        return None
    return {"name": "Debug entitlement (get-task-allow) present in release build",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-489", "owasp": "M10:2023",
            "evidence": "; ".join(i["file"] for i in issues[:3]),
            "remediation": "Remove com.apple.security.get-task-allow from release entitlements. App can be debugged by attackers if present."}


IOS_PLIST_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_arbitrary_loads,
    rule_exception_domains,
    rule_file_sharing,
    rule_get_task_allow,
]
