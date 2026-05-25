"""ios_plist_storage_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("ios_plist_storage_audit_total"):
        return None
    if not s.get("plists_scanned"):
        return {"name": "No plist files - not an IPA upload",
                "severity": "POSITIVE",
                "evidence": "Upload is likely an APK / non-iOS binary",
                "remediation": "No action required.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "iOS plist storage: no sensitive keys detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('plists_scanned', 0)} plist files audited",
            "remediation": "Continue using Keychain for any secret. Never store secrets in NSUserDefaults / Info.plist.",
            "cwe": "CWE-312", "owasp": "M9:2023"}


def rule_sensitive_plist_keys(s):
    hits = s.get("sensitive_plist_hits") or []
    if not hits:
        return None
    return {"name": f"{len(hits)} sensitive plist key(s) detected",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-312", "owasp": "M9:2023",
            "evidence": "; ".join(f"{h['key']} in {h['path']}" for h in hits[:5]),
            "remediation": "Move all secrets to iOS Keychain (kSecClassGenericPassword). Plist files are world-readable via iTunes backup / iMazing."}


IOS_PLIST_STORAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_sensitive_plist_keys,
]
