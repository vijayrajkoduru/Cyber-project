"""anti_debug_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("anti_debug_audit_total"):
        return None
    return {"name": "NO anti-debug protections found",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no Debug.isDebuggerConnected / ptrace markers",
            "remediation": "Add Debug.isDebuggerConnected check at app start; add ptrace(PTRACE_TRACEME, 0, 0, 0) in JNI_OnLoad to prevent gdb/lldb attach. Combine with anti-Frida for proper coverage."}


def rule_java_only(s):
    java = s.get("java_anti_debug") or {}
    native = s.get("native_anti_debug") or []
    if not java or native:
        return None
    return {"name": "Anti-debug is Java-side only (no native ptrace) - bypassable",
            "severity": "LOW", "cvss": "3.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "Java: " + ", ".join(java.keys()),
            "remediation": "Add native-side ptrace(PTRACE_TRACEME) in JNI_OnLoad. Java checks are trivially bypassed via Frida's Java.use(Debug).isDebuggerConnected hook."}


def rule_layered_defense(s):
    java = s.get("java_anti_debug") or {}
    native = s.get("native_anti_debug") or []
    if not (java and native):
        return None
    return {"name": f"Layered anti-debug: Java ({len(java)} mechanism) + Native ({len(native)} .so)",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "Java: " + ", ".join(list(java.keys())[:3]) + f"; Native: {', '.join(native[:3])}",
            "remediation": "Good baseline. For high-value apps add multiple ptrace attempts + checksum the .so on startup so Frida-patched libs fail verification."}


ANTI_DEBUG_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_layered_defense,
    rule_java_only,
]
