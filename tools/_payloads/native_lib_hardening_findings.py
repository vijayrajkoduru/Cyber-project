"""native_lib_hardening — findings rules."""


def rule_positive_emit(s):
    if s.get("native_lib_hardening_total"):
        return None
    return {"name": "Native libs: all bundled .so files hardened",
            "severity": "POSITIVE",
            "evidence": f"{s.get('libs_audited', 0)} libs audited — NX/PIE/RELRO/Canary present on all",
            "remediation": "Continue compiling with -fPIE -fstack-protector-strong -Wl,-z,relro,-z,now.",
            "cwe": "CWE-693", "owasp": "M7:2023"}


def rule_weak_libs(s):
    weak = s.get("weak_libs") or []
    if not weak:
        return None
    # Bucket by criticality
    no_nx = [w for w in weak if "NX" in w["missing"]]
    if no_nx:
        return {"name": f"{len(no_nx)} native lib(s) ship without NX (executable stack)",
                "severity": "HIGH", "cvss": "7.5",
                "cwe": "CWE-119", "owasp": "M7:2023",
                "evidence": "; ".join(f"{w['lib']} missing: {', '.join(w['missing'])}" for w in weak[:5]),
                "remediation": "Recompile with -Wl,-z,noexecstack. Verify with checksec post-build."}
    return {"name": f"{len(weak)} native lib(s) missing hardening mitigations",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M7:2023",
            "evidence": "; ".join(f"{w['lib']}: {', '.join(w['missing'])}" for w in weak[:5]),
            "remediation": "Recompile with -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now."}


NATIVE_LIB_HARDENING_FINDING_RULES = [
    rule_positive_emit,
    rule_weak_libs,
]
