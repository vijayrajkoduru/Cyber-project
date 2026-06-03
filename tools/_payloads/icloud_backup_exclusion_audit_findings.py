"""icloud_backup_exclusion_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("icloud_backup_exclusion_audit_total"):
        return None
    return {"name": "iCloud backup exclusion present or no risky writers",
            "severity": "POSITIVE",
            "evidence": (f"Documents writers={len(s.get('doc_writers') or [])} "
                         f"exclude callers={s.get('backup_exclude_callers', 0)}"),
            "remediation": "Continue marking sensitive caches with NSURLIsExcludedFromBackupKey=true.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_sensitive_backed_up(s):
    co = s.get("sensitive_co_located") or []
    if not co or (s.get("backup_exclude_callers", 0) > 0):
        return None
    return {"name": f"Sensitive symbols written to iCloud-backed directory in {len(co)} class(es)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(co[:6]),
            "remediation": ("Set URL.setResourceValue(true, forKey: .isExcludedFromBackupKey) on token caches / "
                            "private app data, OR move them to Library/Caches/ (not backed up by default).")}


def rule_writers_without_exclusion(s):
    if s.get("sensitive_co_located"):
        return None
    if not s.get("doc_writers") or s.get("backup_exclude_callers", 0) > 0:
        return None
    return {"name": f"{len(s.get('doc_writers') or [])} class(es) write Documents / AppSupport without backup exclusion",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "Writers: " + ", ".join((s.get('doc_writers') or [])[:6]),
            "remediation": "Audit each writer; mark sensitive files with isExcludedFromBackupKey=true or move to Library/Caches/."}


ICLOUD_BACKUP_EXCLUSION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_sensitive_backed_up, rule_writers_without_exclusion]
