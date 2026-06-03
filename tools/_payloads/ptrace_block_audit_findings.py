"""ptrace_block_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ptrace_block_audit_total"):
        return None
    return {"name": "ptrace anti-debug present or no native libs",
            "severity": "POSITIVE",
            "evidence": (f"prctl/PTRACE users={len(s.get('prctl_users') or [])} "
                         f"native libs present={s.get('native_libs_present')}"),
            "remediation": "Continue using prctl(PR_SET_DUMPABLE, 0) and PTRACE_TRACEME in native init.",
            "cwe": "CWE-489", "owasp": "M8:2023"}


def rule_no_ptrace_block(s):
    if not s.get("native_libs_present") or s.get("prctl_users"):
        return None
    return {"name": "Native libs present but no ptrace blocking detected",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-489", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} files scanned. No prctl(PR_SET_DUMPABLE, 0) or PTRACE_TRACEME in any .so.",
            "remediation": ("In JNI_OnLoad / .init_array, call prctl(PR_SET_DUMPABLE, 0) and either "
                            "ptrace(PTRACE_TRACEME) or check /proc/self/status TracerPid. Blocks gdb / "
                            "Frida-server attach.")}


PTRACE_BLOCK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_ptrace_block]
