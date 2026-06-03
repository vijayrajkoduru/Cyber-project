"""content_provider_sqli_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("content_provider_sqli_audit_total"):
        return None
    return {"name": "ContentProvider queries look parameterized",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali scanned; no string-concat selection or unprotected openFile",
            "remediation": "Continue passing args via selectionArgs[]; canonicalize file paths before openFile.",
            "cwe": "CWE-89", "owasp": "M4:2023"}


def rule_cp_sqli(s):
    sus = s.get("sqli_suspects") or []
    if not sus: return None
    return {"name": f"ContentProvider .query() with string-concat selection in {len(sus)} class(es)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-89", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(sus[:6]),
            "remediation": ("Replace selection-string concat with parameterized selectionArgs[]. "
                            "Any installed app querying the provider can inject SQL otherwise.")}


def rule_cp_traversal(s):
    t = s.get("path_traversal_suspects") or []
    if not t: return None
    return {"name": f"ContentProvider openFile() without path canonicalization in {len(t)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-22", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(t[:6]),
            "remediation": ("Call getCanonicalPath() and verify it starts with your app's data dir before "
                            "returning the FileDescriptor. Otherwise content:///../../../etc/passwd-style traversal.")}


CONTENT_PROVIDER_SQLI_AUDIT_FINDING_RULES = [rule_positive_emit, rule_cp_sqli, rule_cp_traversal]
