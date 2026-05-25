"""sharedprefs_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("sharedprefs_audit_total"):
        return None
    return {"name": "SharedPreferences: clean or encrypted usage",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no plain prefs with sensitive keys",
            "remediation": "Continue using EncryptedSharedPreferences from AndroidX Security for any sensitive values.",
            "cwe": "CWE-312", "owasp": "M9:2023"}


def rule_plain_prefs_no_encryption(s):
    plain = s.get("plain_prefs_files") or []
    enc = s.get("encrypted_prefs_files") or []
    if not plain or enc:
        return None
    return {"name": f"{len(plain)} class(es) use plain SharedPreferences, no EncryptedSharedPreferences anywhere",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-312", "owasp": "M9:2023",
            "evidence": "Callers: " + ", ".join(plain[:5]),
            "remediation": "Migrate to androidx.security.crypto.EncryptedSharedPreferences. Plain prefs are world-readable on rooted / debuggable devices."}


def rule_sensitive_keys(s):
    keys = s.get("sensitive_pref_keys") or []
    if not keys:
        return None
    return {"name": f"{len(keys)} sensitive-named pref key(s) detected",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-312", "owasp": "M9:2023",
            "evidence": "Keys: " + ", ".join(keys[:10]),
            "remediation": "Migrate any token/password/secret stored in SharedPreferences to EncryptedSharedPreferences or Android Keystore."}


SHAREDPREFS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_plain_prefs_no_encryption,
    rule_sensitive_keys,
]
