"""method_swizzling_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("method_swizzling_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - swizzle audit N/A",
                "severity": "POSITIVE",
                "evidence": "No iOS source files in unpacked archive",
                "remediation": "Run only against iOS .ipa.",
                "cwe": "CWE-693", "owasp": "M8:2023"}
    return {"name": "Swizzle detection / introspection present",
            "severity": "POSITIVE",
            "evidence": (f"Swizzle users={len(s.get('swizzle_users') or [])} "
                         f"introspection={len(s.get('introspect_users') or [])}"),
            "remediation": "Continue baseline-hashing critical-selector IMP pointers at startup.",
            "cwe": "CWE-693", "owasp": "M8:2023"}


def rule_no_swizzle_defense(s):
    if not s.get("is_ios"):
        return None
    if s.get("introspect_users"):
        return None
    return {"name": "iOS runtime swizzle-detection absent",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} iOS files; no class_getMethodImplementation / method_getImplementation",
            "remediation": ("Hash IMP pointers of critical selectors at +load and re-hash on sensitive "
                            "screen entry; alert if mismatch.")}


METHOD_SWIZZLING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_swizzle_defense]
