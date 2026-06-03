"""hybrid_bridge_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("hybrid_bridge_audit_total"):
        return None
    return {"name": "Hybrid bridge posture clean or no framework detected",
            "severity": "POSITIVE",
            "evidence": f"Frameworks: {s.get('frameworks_detected')} | allowlist={s.get('navigation_allowlist_present')}",
            "remediation": "Continue declaring <allow-navigation> / <allow-intent> with explicit hosts only.",
            "cwe": "CWE-749", "owasp": "M4:2023"}


def rule_no_allowlist(s):
    dp = s.get("dangerous_plugins") or []
    if not dp or s.get("navigation_allowlist_present"):
        return None
    return {"name": f"Hybrid framework with file/camera plugins ({len(dp)}) and no navigation allowlist",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-749", "owasp": "M4:2023",
            "evidence": "Plugin files: " + ", ".join(dp[:6]),
            "remediation": "Add <allow-navigation href=\"https://your-host/*\" /> (Cordova) or server.allowNavigation in capacitor.config (Capacitor). Without it any redirect can trigger filesystem / camera plugins from foreign origins."}


HYBRID_BRIDGE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_allowlist]
