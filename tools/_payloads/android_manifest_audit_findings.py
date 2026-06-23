"""android_manifest_audit — findings rules.

Zero-FP: manifest defaults are not vulnerabilities.
- debuggable graded only when EXPLICITLY true.
- allowBackup graded only when explicitly true AND not scoped by backup rules;
  reliance on the pre-API-31 default is context (INFO), not a finding.
- Exported components graded only when unprotected, NOT a known SDK component,
  AND sensitively named. Other exported components are reported at INFO.
"""


def rule_positive_emit(s):
    if s.get("android_manifest_audit_total"):
        return None
    return {"name": "AndroidManifest: no risky flags detected",
            "severity": "POSITIVE",
            "evidence": "manifest parsed cleanly — no debuggable / unscoped-backup / sensitive-exported issues",
            "remediation": "Maintain current secure-defaults practice.",
            "cwe": "CWE-489", "owasp": "M10:2023"}


def rule_debuggable(s):
    if not s.get("debuggable"):
        return None
    return {"name": "App ships with android:debuggable=true",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-489", "owasp": "M10:2023",
            "evidence": "AndroidManifest.xml: application@android:debuggable=true",
            "remediation": "Remove android:debuggable or set false in release builds. Strip from production AAB/APK."}


def rule_allow_backup(s):
    # Only grade when explicitly enabled AND not scoped by backup rules.
    if not s.get("allow_backup_explicit") or s.get("allow_backup_scoped"):
        return None
    return {"name": "App allows adb backup extraction (no backup scoping rules)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": "AndroidManifest.xml: application@android:allowBackup=true with no fullBackupContent/dataExtractionRules",
            "remediation": "Set android:allowBackup=false on apps handling sensitive data, or scope backups with android:dataExtractionRules / fullBackupContent."}


def rule_allow_backup_default(s):
    # Relying on the pre-API-31 platform default, or backups are scoped — context only.
    if s.get("allow_backup_explicit") is not False and not s.get("allow_backup_scoped"):
        return None
    if not s.get("allow_backup"):
        return None
    scoped = s.get("allow_backup_scoped")
    return {"name": "Backup behaviour relies on platform default / is scoped",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": ("allowBackup not set; pre-API-31 default is true"
                         if not scoped else "backups scoped via dataExtractionRules/fullBackupContent"),
            "remediation": "On API 31+ the backup default is already restrictive. For sensitive apps set android:allowBackup=false explicitly and/or scope dataExtractionRules."}


def rule_exported_components(s):
    exp = s.get("exported_components") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} unprotected sensitive exported component(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-925", "owasp": "M3:2023",
            "evidence": "; ".join(f"{e['type']}: {e['name']}" for e in exp[:5]),
            "remediation": "Add android:permission or set exported=false on each unprotected sensitive component."}


def rule_exported_components_info(s):
    exp = s.get("exported_components_info") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} other exported component(s) (SDK or non-sensitive)",
            "severity": "INFO",
            "cwe": "CWE-925", "owasp": "M3:2023",
            "evidence": "; ".join(f"{e['type']}: {e['name']} ({e.get('reason','')})" for e in exp[:5]),
            "remediation": "Exported SDK components (FileProvider, ad/billing activities) are typically intentional. Confirm each non-sensitive component does not accept untrusted input; otherwise no action."}


def rule_dangerous_permissions(s):
    perms = s.get("dangerous_permissions") or []
    if not perms:
        return None
    return {"name": f"{len(perms)} dangerous permission(s) requested",
            "severity": "MEDIUM", "cvss": "4.3",
            "cwe": "CWE-250", "owasp": "M1:2023",
            "evidence": ", ".join(p.replace("android.permission.", "") for p in perms[:8]),
            "remediation": "Justify each dangerous permission. Drop unused ones. Request at runtime, not install-time."}


ANDROID_MANIFEST_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_debuggable,
    rule_allow_backup,
    rule_allow_backup_default,
    rule_exported_components,
    rule_exported_components_info,
    rule_dangerous_permissions,
]
