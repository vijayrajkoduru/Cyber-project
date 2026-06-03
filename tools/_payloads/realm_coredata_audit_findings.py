"""realm_coredata_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("realm_coredata_audit_total"):
        return None
    realm = s.get("realm_used") or []
    cd = s.get("coredata_used") or []
    if not realm and not cd:
        return {"name": "No Realm / CoreData usage detected",
                "severity": "POSITIVE",
                "evidence": f"{s.get('files_scanned', 0)} files scanned",
                "remediation": "Continue avoiding unencrypted on-device DBs, or keep using SQLCipher / encrypted Realm.",
                "cwe": "CWE-311", "owasp": "M9:2023"}
    return {"name": "Realm / CoreData usage encrypted / protected",
            "severity": "POSITIVE",
            "evidence": (f"Realm encrypted={s.get('realm_encrypted')} CoreData protected={s.get('coredata_protected')}"),
            "remediation": "Keep file-protection level at .complete and rotate Realm encryption key on app major upgrade.",
            "cwe": "CWE-311", "owasp": "M9:2023"}


def rule_realm_no_encryption(s):
    realm = s.get("realm_used") or []
    if not realm or s.get("realm_encrypted"):
        return None
    return {"name": f"Realm DB used in {len(realm)} class(es) without encryption key",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(realm[:5]),
            "remediation": "Pass a 64-byte encryptionKey to RealmConfiguration.Builder, store the key in Android Keystore."}


def rule_coredata_no_protection(s):
    cd = s.get("coredata_used") or []
    if not cd or s.get("coredata_protected"):
        return None
    return {"name": f"CoreData store used in {len(cd)} file(s) without NSFileProtection",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(cd[:5]),
            "remediation": "Set NSPersistentStoreFileProtectionKey to NSFileProtectionComplete (or completeUnlessOpen)."}


REALM_COREDATA_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_realm_no_encryption,
    rule_coredata_no_protection,
]
