"""sqlite_usage_audit — findings rules.

Zero-FP: "presence != usage". SQLite usage inside a bundled SDK is not the
app's storage posture, and a DB *name* containing "auth"/"wallet" is just a
name — not evidence of a sensitive write. Plain-SQLite is graded only for the
app's own callers; sensitive-looking DB names are reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("sqlite_usage_audit_total"):
        return None
    app_sqlite = s.get("app_sqlite_files") or []
    sqlite_files = s.get("sqlite_files") or []
    if not sqlite_files:
        return {"name": "No SQLite usage detected",
                "severity": "POSITIVE",
                "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
                "remediation": "No action required.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    if not app_sqlite:
        return {"name": "SQLite used only by bundled libraries (no app-code usage)",
                "severity": "POSITIVE",
                "evidence": f"SQLite callers: {len(sqlite_files)} (all in SDK/test paths)",
                "remediation": "No app-controlled SQLite storage to harden.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "SQLite usage is encrypted (SQLCipher present)",
            "severity": "POSITIVE",
            "evidence": f"SQLite callers: {len(sqlite_files)}; SQLCipher callers: {len(s.get('sqlcipher_files') or [])}",
            "remediation": "Continue using SQLCipher with a strong key stored in Android Keystore.",
            "cwe": "CWE-311", "owasp": "M9:2023"}


def rule_plain_sqlite(s):
    sqlite = s.get("app_sqlite_files") or []
    sqlcipher = s.get("sqlcipher_files") or []
    if not sqlite or sqlcipher:
        return None
    return {"name": f"{len(sqlite)} app class(es) use plain SQLite, no SQLCipher anywhere",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "Callers: " + ", ".join(sqlite[:5]),
            "remediation": "Migrate to SQLCipher (net.sqlcipher) or Room with SupportFactory. Store the key in Android Keystore."}


def rule_sensitive_db_name(s):
    names = s.get("sensitive_db_names") or []
    if not names:
        return None
    # Name-only heuristic: a DB called "wallet.db" is not proof of a plaintext
    # sensitive write. Report at INFO so it can be manually confirmed.
    return {"name": f"{len(names)} DB name(s) suggest sensitive data (name-based hint)",
            "severity": "INFO",
            "cwe": "CWE-311", "owasp": "M9:2023",
            "evidence": "DBs: " + ", ".join(names),
            "remediation": "Confirm whether these databases actually store credentials/financial/PII. If they do, encrypt with SQLCipher + an Android Keystore-backed key. The name alone is not a vulnerability."}


SQLITE_USAGE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_plain_sqlite,
    rule_sensitive_db_name,
]
