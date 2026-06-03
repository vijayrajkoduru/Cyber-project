"""keystore_keychain_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("keystore_keychain_audit_total"):
        return None
    return {"name": "Secure-element key storage posture clean",
            "severity": "POSITIVE",
            "evidence": (f"Android KeyStore users={len(s.get('android_keystore_files') or [])} "
                         f"user-auth gated={s.get('android_user_auth_files', 0)} | "
                         f"iOS Keychain users={len(s.get('ios_keychain_files') or [])} "
                         f"strong access={s.get('ios_strong_access_files', 0)}"),
            "remediation": "Continue using AndroidKeyStore + setUserAuthenticationRequired(true) and ThisDeviceOnly-suffixed accessibility on iOS.",
            "cwe": "CWE-321", "owasp": "M9:2023"}


def rule_android_no_user_auth(s):
    ks = s.get("android_keystore_files") or []
    auth = s.get("android_user_auth_files") or 0
    if not ks or auth > 0:
        return None
    return {"name": f"Android KeyStore used in {len(ks)} class(es) without user-authentication gate",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-321", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(ks[:6]),
            "remediation": ("Call setUserAuthenticationRequired(true) on KeyGenParameterSpec for keys that "
                            "protect credentials / payment tokens; require biometric or device-credential "
                            "auth before key release.")}


def rule_ios_weak_accessible(s):
    weak = s.get("ios_weak_access_files") or []
    if not weak:
        return None
    return {"name": f"iOS Keychain weak accessibility (kSecAttrAccessibleAlways / AfterFirstUnlock) in {len(weak)} file(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-321", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(weak[:6]),
            "remediation": ("Replace kSecAttrAccessibleAlways with "
                            "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly (sensitive) or "
                            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly (general). "
                            "Block backup-restore credential leakage.")}


KEYSTORE_KEYCHAIN_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_android_no_user_auth,
    rule_ios_weak_accessible,
]
