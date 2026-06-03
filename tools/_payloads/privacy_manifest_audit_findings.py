"""privacy_manifest_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("privacy_manifest_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - Privacy Manifest N/A",
                "severity": "POSITIVE", "evidence": "No iOS sources",
                "remediation": "Run only against .ipa.",
                "cwe": "CWE-359", "owasp": "M9:2023"}
    return {"name": "Privacy Manifest posture clean",
            "severity": "POSITIVE",
            "evidence": f"PrivacyInfo.xcprivacy found={s.get('privacy_manifest_found')} | required-reason APIs={s.get('required_reason_apis_used')}",
            "remediation": "Continue declaring every required-reason API in PrivacyInfo.xcprivacy.",
            "cwe": "CWE-359", "owasp": "M9:2023"}


def rule_no_manifest(s):
    if not s.get("is_ios") or s.get("privacy_manifest_found"):
        return None
    return {"name": "iOS app missing PrivacyInfo.xcprivacy",
            "severity": "HIGH", "cvss": "5.5",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "No PrivacyInfo.xcprivacy file in unpacked .ipa",
            "remediation": "Add PrivacyInfo.xcprivacy to your bundle declaring required-reason APIs + tracking domains. Apple App Store rejects iOS 17+ submissions without it."}


def rule_missing_declarations(s):
    md = s.get("missing_required_reason_declarations") or []
    if not md: return None
    return {"name": f"{len(md)} required-reason API used without declaration",
            "severity": "MEDIUM", "cvss": "4.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "Missing declarations: " + ", ".join(md[:8]),
            "remediation": "Declare each in PrivacyInfo.xcprivacy NSPrivacyAccessedAPITypes with valid NSPrivacyAccessedAPITypeReasons code (e.g. CA92.1 for UserDefaults)."}


PRIVACY_MANIFEST_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_manifest, rule_missing_declarations]
