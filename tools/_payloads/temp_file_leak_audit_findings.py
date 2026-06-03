"""temp_file_leak_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("temp_file_leak_audit_total"):
        return None
    return {"name": "No temp / cache writes near sensitive data",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} files scanned - no risky temp writers detected",
            "remediation": "Continue using app-private storage; clear temp dirs in onTrimMemory / didReceiveMemoryWarning.",
            "cwe": "CWE-377", "owasp": "M9:2023"}


def rule_sensitive_near_temp(s):
    co = s.get("co_located_sensitive") or []
    if not co:
        return None
    return {"name": f"{len(co)} class(es) write temp files in same scope as sensitive keys",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-377", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(co[:6]),
            "remediation": ("Never persist secrets to /cache/ or NSTemporaryDirectory; "
                            "redirect to EncryptedFile / Keychain (.complete protection).")}


def rule_temp_writes_present(s):
    if s.get("co_located_sensitive"):
        return None  # already covered by the higher-severity rule
    a = s.get("android_temp_files") or []
    i = s.get("ios_temp_files") or []
    if not (a or i):
        return None
    return {"name": f"Temp / cache file writes detected ({len(a)+len(i)} class(es))",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-377", "owasp": "M9:2023",
            "evidence": (f"Android={len(a)} files | iOS={len(i)} files. "
                         "No sensitive co-location detected; informational."),
            "remediation": "Audit each temp writer; clear contents on app foreground if user data is involved."}


TEMP_FILE_LEAK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_sensitive_near_temp,
    rule_temp_writes_present,
]
