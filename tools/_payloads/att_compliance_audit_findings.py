"""att_compliance_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("att_compliance_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - ATT N/A",
                "severity": "POSITIVE", "evidence": "No iOS sources / plist",
                "remediation": "Run only against .ipa.",
                "cwe": "CWE-359", "owasp": "M9:2023"}
    return {"name": "ATT compliance posture clean",
            "severity": "POSITIVE",
            "evidence": (f"IDFA users={len(s.get('idfa_users') or [])} "
                         f"ATT requests={s.get('att_request_callers', 0)} "
                         f"NSUserTrackingUsageDescription={s.get('nsusertrackingusagedescription_present')}"),
            "remediation": "Continue calling ATTrackingManager.requestTrackingAuthorization before IDFA access.",
            "cwe": "CWE-359", "owasp": "M9:2023"}


def rule_no_att_request(s):
    if not s.get("is_ios"): return None
    if not s.get("idfa_users") or s.get("att_request_callers", 0) > 0: return None
    return {"name": "IDFA accessed without ATTrackingManager.requestTrackingAuthorization",
            "severity": "HIGH", "cvss": "5.5",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": f"IDFA users: {', '.join((s.get('idfa_users') or [])[:6])}",
            "remediation": "Call ATTrackingManager.requestTrackingAuthorization(completionHandler:) BEFORE every IDFA access on iOS 14.5+. App Review will reject otherwise."}


def rule_no_purpose_string(s):
    if not s.get("is_ios"): return None
    if not s.get("idfa_users") or s.get("nsusertrackingusagedescription_present"): return None
    return {"name": "NSUserTrackingUsageDescription missing from Info.plist",
            "severity": "MEDIUM", "cvss": "4.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "IDFA access detected; no purpose-string in Info.plist",
            "remediation": "Add <key>NSUserTrackingUsageDescription</key><string>...</string> to Info.plist with a clear purpose; required for ATT prompt to render."}


ATT_COMPLIANCE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_att_request, rule_no_purpose_string]
