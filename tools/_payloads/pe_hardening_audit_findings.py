"""pe_hardening_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("pe_hardening_audit_total"):
        return None
    audited = s.get("pe_files_audited", 0)
    if audited == 0:
        return {"name": "No Windows PE binaries in upload",
                "severity": "POSITIVE",
                "evidence": "Not a Windows-targeted binary",
                "remediation": "No action required.",
                "cwe": "CWE-693", "owasp": "M7:2023"}
    return {"name": "PE hardening: all Windows binaries have ASLR + DEP + CFG",
            "severity": "POSITIVE",
            "evidence": f"{audited} PE binaries audited — all mitigations present",
            "remediation": "Continue building with /DYNAMICBASE /NXCOMPAT /GUARD:CF.",
            "cwe": "CWE-693", "owasp": "M7:2023"}


def rule_weak_pe(s):
    weak = s.get("weak_pe_binaries") or []
    if not weak:
        return None
    return {"name": f"{len(weak)} Windows PE binary(ies) missing security mitigations",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-693", "owasp": "M7:2023",
            "evidence": "; ".join(f"{w['file']}: missing {', '.join(w['missing'])}" for w in weak[:5]),
            "remediation": "Build with /DYNAMICBASE (ASLR), /NXCOMPAT (DEP), /GUARD:CF (CFG). Sign with Authenticode."}


PE_HARDENING_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_weak_pe,
]
