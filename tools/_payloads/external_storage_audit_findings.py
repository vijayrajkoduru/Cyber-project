"""external_storage_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("external_storage_audit_total"):
        return None
    return {"name": "External storage: no risky permissions or hardcoded paths",
            "severity": "POSITIVE",
            "evidence": f"Manifest + {s.get('files_scanned', 0)} smali files scanned",
            "remediation": "Continue using scoped-storage MediaStore / app-private context.getFilesDir().",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_external_perms(s):
    perms = s.get("external_perms") or []
    if not perms:
        return None
    has_manage = "android.permission.MANAGE_EXTERNAL_STORAGE" in perms
    sev = "HIGH" if has_manage else "MEDIUM"
    return {"name": f"App requests {len(perms)} external-storage permission(s)" + (" including MANAGE_EXTERNAL_STORAGE" if has_manage else ""),
            "severity": sev, "cvss": "6.5" if has_manage else "5.0",
            "cwe": "CWE-276", "owasp": "M9:2023",
            "evidence": "Perms: " + ", ".join(p.split(".")[-1] for p in perms),
            "remediation": "Migrate to scoped-storage (Android 10+). MANAGE_EXTERNAL_STORAGE requires Play Store justification + reviewer approval."}


def rule_hardcoded_external_paths(s):
    paths = s.get("hardcoded_external_paths") or []
    if not paths:
        return None
    return {"name": f"{len(paths)} hardcoded /sdcard or /storage path(s)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-538", "owasp": "M9:2023",
            "evidence": "Paths: " + "; ".join(paths[:5]),
            "remediation": "Replace hardcoded /sdcard paths with Environment.getExternalStorageDirectory() or scoped storage APIs."}


EXTERNAL_STORAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_external_perms,
    rule_hardcoded_external_paths,
]
