"""backup_extraction_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("backup_extraction_audit_total"):
        return None
    return {"name": "Backup policy: allowBackup=false OR strict rules in place",
            "severity": "POSITIVE",
            "evidence": f"allowBackup={s.get('allow_backup')}; rules={s.get('backup_rules_file') or 'n/a'}",
            "remediation": "Continue blocking unrestricted backups for any app handling sensitive data.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_allow_backup_no_rules(s):
    if not (s.get("allow_backup") == "true" and not s.get("full_backup_content") and not s.get("data_extraction_rules")):
        return None
    return {"name": "App allows unrestricted ADB / cloud backup of ALL app data",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "android:allowBackup=true with NO fullBackupContent + NO dataExtractionRules",
            "remediation": "Set android:allowBackup=\"false\" OR provide android:fullBackupContent=\"@xml/backup_rules\" with an explicit exclude list for databases / SharedPreferences containing secrets."}


def rule_allow_backup_with_rules(s):
    if not (s.get("allow_backup") == "true" and (s.get("full_backup_content") or s.get("data_extraction_rules"))):
        return None
    rules = s.get("backup_rules_summary") or {}
    return {"name": "Backups allowed but ruled-in/-out via XML policy",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": f"includes: {len((rules.get('includes') or []))}, excludes: {len((rules.get('excludes') or []))}",
            "remediation": "Review the backup-rules XML manually - ensure databases / SharedPreferences containing secrets are explicitly excluded."}


BACKUP_EXTRACTION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_allow_backup_no_rules,
    rule_allow_backup_with_rules,
]
