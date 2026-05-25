"""sqlite_usage_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("sqlite_usage_audit_total"):
        return None
    sqlite_files = s.get("sqlite_files") or []
    if not sqlite_files:
        return {"name": "No SQLite usage detected",
                "severity": "POSITIVE",
                "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
                "remediation": "No action required.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "SQLite usage is encrypted (SQLCipher present)",
            "severity": "POSITIVE",
            "evidence": f"SQLite callers: {len(sqlite_files)}; SQLCipher callers: {len(s.get('sqlcipher_files') or [])}",
            "remediation": "Continue using SQLCipher with a strong key stored in Android Keystore.",
            "cwe": "CWE-311", "owasp": "M9:2023"}


def rule_plain_sqlite(s):
    sqlite = s.get("sqlite_files") or []
    sqlcipher = s.get("sqlcipher_files") or []
    if not sqlite or sqlcipher:
        return None
    return {"name": f"{len(sqlite)} class(es) use plain SQLite, no SQLCipher anywhere",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "Callers: " + ", ".join(sqlite[:5]),
            "remediation": "Migrate to SQLCipher (net.sqlcipher) or Room with SupportFactory. Store the key in Android Keystore."}


def rule_sensitive_db_name(s):
    names = s.get("sensitive_db_names") or []
    if not names:
        return None
    return {"name": f"{len(names)} DB name(s) suggest sensitive data",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "DBs: " + ", ".join(names),
            "remediation": "Encrypt any DB that stores credentials, financial, or PII data. Use SQLCipher + Android Keystore-backed key."}


SQLITE_USAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_plain_sqlite,
    rule_sensitive_db_name,
]
