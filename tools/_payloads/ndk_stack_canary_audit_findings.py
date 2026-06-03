"""ndk_stack_canary_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ndk_stack_canary_audit_total"):
        return None
    return {"name": "NDK hardening posture clean",
            "severity": "POSITIVE",
            "evidence": f"{s.get('libs_scanned', 0)} .so file(s) - all carry canary + RELRO + PIE",
            "remediation": "Continue building with -fstack-protector-strong -Wl,-z,relro,-z,now -fPIE.",
            "cwe": "CWE-121", "owasp": "M7:2023"}


def rule_no_canary(s):
    c = s.get("no_canary") or []
    if not c: return None
    return {"name": f"{len(c)} native lib(s) without stack canary",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-121", "owasp": "M7:2023",
            "evidence": "Libs: " + ", ".join(c[:6]),
            "remediation": "Rebuild with -fstack-protector-strong; protects against stack-buffer overflows."}


def rule_no_relro(s):
    r = s.get("no_relro") or []
    if not r: return None
    return {"name": f"{len(r)} native lib(s) without full RELRO + BIND_NOW",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-1325", "owasp": "M7:2023",
            "evidence": "Libs: " + ", ".join(r[:6]),
            "remediation": "Link with -Wl,-z,relro -Wl,-z,now. Hardens GOT against rewrite via format-string."}


def rule_no_pie(s):
    p = s.get("no_pie") or []
    if not p: return None
    return {"name": f"{len(p)} native lib(s) not Position-Independent (ASLR weakened)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-1305", "owasp": "M7:2023",
            "evidence": "Libs: " + ", ".join(p[:6]),
            "remediation": "Build with -fPIE -pie. PIE is mandatory for Android since API 21 (2014)."}


NDK_STACK_CANARY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_canary, rule_no_relro, rule_no_pie]
