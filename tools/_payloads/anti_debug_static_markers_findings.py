"""anti_debug_static_markers — findings rules."""


def rule_positive_emit(s):
    n = s.get("anti_debug_static_markers_total", 0)
    if n > 0: return None
    return {"name": "Anti-debug / anti-Frida detection NOT present",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 anti-debug markers",
            "remediation": "For apps handling financial transactions / DRM-protected "
                           "content / sensitive PII, add Debug.isDebuggerConnected() + "
                           "ptrace + sysctl checks. For Frida-aware defense: detect "
                           "frida-server processes and tampered loaded libraries at boot."}


def rule_anti_debug_present(s):
    n = s.get("anti_debug_static_markers_total", 0)
    if n == 0: return None
    sample = s.get("anti_debug_markers_found", [])[:5]
    return {"name": f"Anti-debug / Frida detection present ({n} marker(s))",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": "markers: " + ", ".join(m["marker"] for m in sample),
            "remediation": "Good. Combine static-marker detection with runtime "
                           "integrity checks (e.g. periodic re-check, code signature "
                           "verify, server-side attestation)."}


ANTI_DEBUG_STATIC_MARKERS_FINDING_RULES = [
    rule_positive_emit,
    rule_anti_debug_present,
]
