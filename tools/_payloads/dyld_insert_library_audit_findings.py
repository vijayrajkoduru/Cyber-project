"""dyld_insert_library_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("dyld_insert_library_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - DYLD audit N/A",
                "severity": "POSITIVE",
                "evidence": "No iOS source files in unpacked archive",
                "remediation": "Run dyld audit only against .ipa binaries.",
                "cwe": "CWE-693", "owasp": "M8:2023"}
    return {"name": "DYLD anti-injection signals present",
            "severity": "POSITIVE",
            "evidence": (f"env checks={len(s.get('env_inspection_callers') or [])} "
                         f"image checks={len(s.get('image_inspection_callers') or [])}"),
            "remediation": "Continue inspecting _dyld_image_count and DYLD_INSERT_LIBRARIES env at startup.",
            "cwe": "CWE-693", "owasp": "M8:2023"}


def rule_no_dyld_guard(s):
    if not s.get("is_ios"):
        return None
    if s.get("env_inspection_callers") or s.get("image_inspection_callers"):
        return None
    return {"name": "iOS app has no DYLD_INSERT_LIBRARIES / image-list guard",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} iOS files scanned; no DYLD env-var / image-list inspection",
            "remediation": ("On startup: getenv(\"DYLD_INSERT_LIBRARIES\") != NULL -> exit; "
                            "iterate _dyld_image_count and assert no /usr/lib/libCheckra1n.dylib / Substrate / "
                            "Cycript image in the list.")}


DYLD_INSERT_LIBRARY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_dyld_guard]
