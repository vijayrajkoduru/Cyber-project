"""image_cache_paths_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("image_cache_paths_audit_total"):
        return None
    return {"name": "Image / video cache paths: no unsafe external paths",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no /sdcard or /storage/emulated paths",
            "remediation": "Continue using app-private cache dir (context.getCacheDir()) or scoped-storage MediaStore.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_unsafe_paths(s):
    paths = s.get("unsafe_paths") or []
    if not paths:
        return None
    return {"name": f"{len(paths)} hardcoded path(s) under external storage",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-538", "owasp": "M9:2023",
            "evidence": "Paths: " + "; ".join(paths[:5]),
            "remediation": "Move cache to context.getCacheDir() (app-private). External-storage paths are world-readable on Android <10 and require runtime permission on newer."}


IMAGE_CACHE_PATHS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_unsafe_paths,
]
