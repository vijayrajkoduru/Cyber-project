"""removable_storage_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("removable_storage_audit_total"):
        return None
    return {"name": "Removable / shared storage usage clean",
            "severity": "POSITIVE",
            "evidence": (f"{len(s.get('ext_storage_writers') or [])} ext-storage writers, "
                         f"{len(s.get('ext_storage_permission_files') or [])} permission entries, "
                         f"legacy={s.get('legacy_external_storage')}"),
            "remediation": "Continue using scoped storage (getFilesDir / app-private MediaStore APIs).",
            "cwe": "CWE-922", "owasp": "M9:2023"}


def rule_sensitive_to_external(s):
    co = s.get("sensitive_co_located") or []
    if not co:
        return None
    return {"name": f"{len(co)} class(es) write external storage in same scope as sensitive keys",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-922", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(co[:6]),
            "remediation": ("Move sensitive writes to internal storage (getFilesDir / EncryptedFile). "
                            "External storage is world-readable on devices < Android 10 and any app with "
                            "READ_EXTERNAL_STORAGE can exfiltrate.")}


def rule_external_with_permission(s):
    if s.get("sensitive_co_located"):
        return None  # covered by higher-severity rule
    w = s.get("ext_storage_writers") or []
    perms = s.get("ext_storage_permission_files") or []
    if not (w and perms):
        return None
    return {"name": f"App declares WRITE_EXTERNAL_STORAGE and writes external storage in {len(w)} class(es)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-922", "owasp": "M9:2023",
            "evidence": "Writers: " + ", ".join(w[:6]),
            "remediation": ("Audit each external write; migrate to MediaStore + scoped storage for "
                            "Android 10+. Remove WRITE_EXTERNAL_STORAGE from the manifest if not strictly required.")}


def rule_legacy_external_storage(s):
    if not s.get("legacy_external_storage"):
        return None
    return {"name": "App opts OUT of scoped storage (requestLegacyExternalStorage=true)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-922", "owasp": "M9:2023",
            "evidence": "requestLegacyExternalStorage / preserveLegacyExternalStorage attribute present in manifest",
            "remediation": ("Remove requestLegacyExternalStorage and migrate to MediaStore / SAF before "
                            "targeting Android 11+ (legacy mode is no longer honored).")}


REMOVABLE_STORAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_sensitive_to_external,
    rule_external_with_permission,
    rule_legacy_external_storage,
]
