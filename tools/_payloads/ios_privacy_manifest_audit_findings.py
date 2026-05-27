"""ios_privacy_manifest_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("ios_privacy_manifest_audit_total"):
        return None
    if s.get("xcprivacy_missing"):
        return None
    return {"name": "iOS Privacy Manifest present and well-formed",
            "severity": "POSITIVE",
            "evidence": "PrivacyInfo.xcprivacy parsed cleanly with valid required-reason codes",
            "remediation": "Re-validate after any new SDK is added; Apple updates required-reason API list quarterly.",
            "cwe": "CWE-359", "owasp": "M6:2023"}


def rule_xcprivacy_missing(s):
    if not s.get("xcprivacy_missing"):
        return None
    return {"name": "PrivacyInfo.xcprivacy missing (App Store submission blocker)",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-359", "owasp": "M6:2023",
            "evidence": "no PrivacyInfo.xcprivacy file found in app bundle",
            "remediation": "Add PrivacyInfo.xcprivacy at the app bundle root. Declare NSPrivacyTracking, NSPrivacyCollectedDataTypes, and NSPrivacyAccessedAPITypes per Apple's required-reason API list."}


def rule_tracking_no_domains(s):
    issues = [i for i in (s.get("privacy_issues") or []) if i.get("issue") == "tracking-true-but-empty-domains"]
    if not issues:
        return None
    return {"name": "NSPrivacyTracking=true but NSPrivacyTrackingDomains empty",
            "severity": "HIGH", "cvss": "6.0",
            "cwe": "CWE-359", "owasp": "M6:2023",
            "evidence": "; ".join(i["file"] for i in issues[:5]),
            "remediation": "Either set NSPrivacyTracking=false OR enumerate every third-party tracking domain in NSPrivacyTrackingDomains. App Store will reject otherwise."}


def rule_required_reason_bad(s):
    bad = [i for i in (s.get("privacy_issues") or []) if i.get("issue") in ("bad-required-reason", "empty-required-reason")]
    if not bad:
        return None
    return {"name": f"NSPrivacyAccessedAPITypes — {len(bad)} required-reason issue(s)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-359", "owasp": "M6:2023",
            "evidence": "; ".join(f"{i['file']}: {i.get('category', '?').split('Category')[-1]} {i.get('codes', '(empty)')}" for i in bad[:5]),
            "remediation": "Each NSPrivacyAccessedAPIType must include valid NSPrivacyAccessedAPITypeReasons codes from Apple's approved list."}


def rule_collected_data_missing(s):
    miss = [i for i in (s.get("privacy_issues") or []) if i.get("issue") == "NSPrivacyCollectedDataTypes-missing"]
    if not miss:
        return None
    return {"name": "NSPrivacyCollectedDataTypes declaration missing",
            "severity": "MEDIUM", "cvss": "4.3",
            "cwe": "CWE-359", "owasp": "M6:2023",
            "evidence": "; ".join(i["file"] for i in miss[:5]),
            "remediation": "Declare every data type the app collects (NSPrivacyCollectedDataTypes is required even when empty — use an empty array if the app collects nothing)."}


IOS_PRIVACY_MANIFEST_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_xcprivacy_missing,
    rule_tracking_no_domains,
    rule_required_reason_bad,
    rule_collected_data_missing,
]
