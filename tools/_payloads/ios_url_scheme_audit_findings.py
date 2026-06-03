"""ios_url_scheme_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ios_url_scheme_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - URL scheme audit N/A",
                "severity": "POSITIVE", "evidence": "No plist found",
                "remediation": "Run only against .ipa.",
                "cwe": "CWE-940", "owasp": "M4:2023"}
    return {"name": "iOS URL scheme posture clean",
            "severity": "POSITIVE",
            "evidence": (f"Custom schemes={len(s.get('declared_schemes') or [])} "
                         f"Universal Link={s.get('universal_link_present')}"),
            "remediation": "Continue using Universal Links for auth flows; verify caller via openURL options.",
            "cwe": "CWE-940", "owasp": "M4:2023"}


def rule_custom_scheme_no_universal(s):
    if not s.get("is_ios"): return None
    sch = s.get("declared_schemes") or []
    if not sch or s.get("universal_link_present"): return None
    return {"name": f"iOS custom URL scheme(s) without Universal Link backup ({len(sch)})",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-940", "owasp": "M4:2023",
            "evidence": "Schemes: " + ", ".join(sch[:6]),
            "remediation": ("Custom schemes can be hijacked by a later-installed competing app. "
                            "Migrate auth flows to Universal Links: add com.apple.developer.associated-domains "
                            "+ host apple-app-site-association on your domain.")}


IOS_URL_SCHEME_AUDIT_FINDING_RULES = [rule_positive_emit, rule_custom_scheme_no_universal]
