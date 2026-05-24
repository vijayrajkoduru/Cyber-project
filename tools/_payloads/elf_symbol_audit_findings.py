"""elf_symbol_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("elf_symbol_audit_total"):
        return None
    audited = s.get("elfs_audited", 0)
    if audited == 0:
        return {"name": "No ELF binaries to audit",
                "severity": "POSITIVE",
                "evidence": "Not an ELF-bearing upload",
                "remediation": "No action required.",
                "cwe": "CWE-200", "owasp": "M9:2023"}
    return {"name": "ELF audit: no dangerous imports, properly stripped",
            "severity": "POSITIVE",
            "evidence": f"{audited} ELF binaries audited — no gets/strcpy/sprintf imports, debug symbols stripped",
            "remediation": "Continue using safer alternatives (snprintf, strncpy_s).",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_dangerous_imports(s):
    issues = [i for i in (s.get("elf_issues") or []) if i.get("dangerous_imports")]
    if not issues:
        return None
    return {"name": f"{len(issues)} ELF binary(ies) import unsafe libc functions",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-242", "owasp": "M7:2023",
            "evidence": "; ".join(f"{i['file']}: {', '.join(i['dangerous_imports'])}" for i in issues[:5]),
            "remediation": "Replace gets→fgets, strcpy→strncpy/strlcpy, sprintf→snprintf. Use -D_FORTIFY_SOURCE=2."}


def rule_debug_symbols(s):
    issues = [i for i in (s.get("elf_issues") or []) if i.get("issue") == "unstripped-debug-symbols"]
    if not issues:
        return None
    return {"name": f"{len(issues)} ELF binary(ies) ship with debug symbols",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "; ".join(i["file"] for i in issues[:5]),
            "remediation": "Run `strip --strip-debug` on release builds. Reduces binary size + hides function names from reverse engineering."}


ELF_SYMBOL_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_dangerous_imports,
    rule_debug_symbols,
]
