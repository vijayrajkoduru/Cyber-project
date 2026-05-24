"""android_manifest_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("android_manifest_audit_total"):
        return None
    return {"name": "AndroidManifest: no risky flags detected",
            "severity": "POSITIVE",
            "evidence": "manifest parsed cleanly — no debuggable/allowBackup/exported issues",
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
    if not s.get("allow_backup"):
        return None
    return {"name": "App allows adb backup extraction",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": "AndroidManifest.xml: application@android:allowBackup=true",
            "remediation": "Set android:allowBackup=false on apps handling sensitive user data."}


def rule_exported_components(s):
    exp = s.get("exported_components") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} exported component(s) without permission",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-925", "owasp": "M3:2023",
            "evidence": "; ".join(f"{e['type']}: {e['name']}" for e in exp[:5]),
            "remediation": "Add android:permission or set exported=false on each unprotected component."}


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
    rule_exported_components,
    rule_dangerous_permissions,
]
