"""auth_token_storage_audit — findings rules."""


def rule_positive_emit(s):
    tokens = s.get("token_files") or []
    insec = s.get("insecure_token_storage_files") or []
    sec = s.get("secure_token_storage_files") or []
    if not tokens:
        return {"name": "No auth-token references in DEX",
                "severity": "POSITIVE",
                "cwe": "CWE-922", "owasp": "M9:2023",
                "evidence": f"scanned {s.get('files_scanned', 0)} files, no token markers",
                "remediation": "Stateless app or tokens fully server-side."}
    if not insec and sec:
        return {"name": f"Token files use secure storage ({len(sec)} files)",
                "severity": "POSITIVE",
                "cwe": "CWE-922", "owasp": "M9:2023",
                "evidence": f"secure markers: EncryptedSharedPreferences / Keychain / Keystore",
                "remediation": "Maintain. For highest assurance: bind storage to "
                               "BiometricPrompt CryptoObject so token decryption "
                               "requires user re-auth on rooted/stolen device."}
    return None


def rule_insecure_token_storage(s):
    insec = s.get("insecure_token_storage_files") or []
    if not insec: return None
    return {"name": f"Auth tokens stored in INSECURE locations ({len(insec)} files)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-922", "owasp": "M9:2023",
            "evidence": " | ".join(insec[:5]),
            "remediation": "Migrate to: (Android) Jetpack EncryptedSharedPreferences "
                           "with MasterKey from AndroidKeyStore; (iOS) Keychain with "
                           "kSecAttrAccessibleWhenUnlockedThisDeviceOnly. Plain "
                           "SharedPreferences / NSUserDefaults are readable by anyone "
                           "with file-system access on a rooted/jailbroken device + "
                           "are included in adb backups + iCloud backups."}


def rule_mixed_storage(s):
    insec = s.get("insecure_token_storage_files") or []
    sec = s.get("secure_token_storage_files") or []
    if not (insec and sec): return None
    return {"name": "Mixed token storage: secure + insecure paths both present",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-922", "owasp": "M9:2023",
            "evidence": f"insecure files: {len(insec)} | secure files: {len(sec)}",
            "remediation": "Some code paths use Keystore/Keychain; others fall back "
                           "to plain prefs. Audit the fallback paths — usually a leftover "
                           "from migration. Remove plain storage paths entirely."}


AUTH_TOKEN_STORAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_insecure_token_storage,
    rule_mixed_storage,
]
