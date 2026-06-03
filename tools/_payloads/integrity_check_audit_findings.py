"""integrity_check_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("integrity_check_audit_total"):
        return None
    return {"name": "Runtime integrity / signature checks present",
            "severity": "POSITIVE",
            "evidence": (f"Android sig calls={len(s.get('android_sig_calls') or [])} "
                         f"iOS codesign={len(s.get('ios_codesign') or [])}"),
            "remediation": "Continue verifying signing cert SHA-256 / Mach-O codesign on app start.",
            "cwe": "CWE-345", "owasp": "M8:2023"}


def rule_no_integrity_check(s):
    if s.get("android_sig_calls") or s.get("ios_codesign"):
        return None
    return {"name": "App does not verify its own signature / code-signing at runtime",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-345", "owasp": "M8:2023",
            "evidence": (f"No PackageManager.GET_SIGNATURES or SecCodeCheckValidity calls in "
                         f"{s.get('files_scanned', 0)} smali/.swift/.m files"),
            "remediation": ("Android: PackageManager.getPackageInfo(GET_SIGNING_CERTIFICATES) -> SHA-256 -> "
                            "compare to baked-in baseline. iOS: SecCodeCopySelf + SecCodeCheckValidity. "
                            "Bail out if integrity fails.")}


INTEGRITY_CHECK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_integrity_check]
