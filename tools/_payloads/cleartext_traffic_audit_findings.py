"""cleartext_traffic_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("cleartext_traffic_audit_total"):
        return None
    return {"name": "TLS-only network policy enforced",
            "severity": "POSITIVE",
            "evidence": (f"Android cleartext blocked={s.get('android_cleartext_blocked')} | "
                         f"iOS ATS arbitrary loads={s.get('ios_ats_arbitrary_loads')}"),
            "remediation": "Continue with usesCleartextTraffic=\"false\" + NSAllowsArbitraryLoads=false.",
            "cwe": "CWE-319", "owasp": "M3:2023"}


def rule_android_cleartext(s):
    if not s.get("android_cleartext_allowed") or s.get("android_cleartext_blocked"):
        return None
    return {"name": "Android: usesCleartextTraffic=\"true\" in manifest",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "AndroidManifest.application@usesCleartextTraffic=true (or NSC cleartextTrafficPermitted=true)",
            "remediation": ("Set usesCleartextTraffic=\"false\" on <application>. Add a "
                            "network_security_config.xml with <base-config cleartextTrafficPermitted=\"false\">.")}


def rule_ios_ats_open(s):
    if not s.get("ios_ats_arbitrary_loads"):
        return None
    return {"name": "iOS: NSAllowsArbitraryLoads=true (App Transport Security disabled)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Info.plist NSAppTransportSecurity.NSAllowsArbitraryLoads=true",
            "remediation": ("Remove NSAllowsArbitraryLoads. If a single domain truly needs HTTP, "
                            "add it under NSExceptionDomains with NSExceptionAllowsInsecureHTTPLoads + justification.")}


def rule_ios_ats_exceptions(s):
    if s.get("ios_ats_arbitrary_loads"):
        return None
    ex = s.get("ios_ats_exception_domains") or []
    if not ex:
        return None
    return {"name": f"iOS: NSExceptionDomains with insecure HTTP allowance ({len(ex)} domain(s))",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-319", "owasp": "M3:2023",
            "evidence": "Files: " + ", ".join(ex[:4]),
            "remediation": "Audit each exception. Migrate listed domains to HTTPS; remove exception once vendor ships TLS."}


CLEARTEXT_TRAFFIC_AUDIT_FINDING_RULES = [rule_positive_emit, rule_android_cleartext, rule_ios_ats_open, rule_ios_ats_exceptions]
