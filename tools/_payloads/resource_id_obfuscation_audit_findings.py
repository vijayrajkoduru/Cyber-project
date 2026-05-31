"""resource_id_obfuscation_audit — findings rules."""


def rule_positive_emit(s):
    ratio = s.get("short_layout_ratio_pct", -1)
    if ratio >= 40:
        return {"name": f"Resources appear shrunk/obfuscated ({ratio}% short layout names)",
                "severity": "POSITIVE",
                "cwe": "CWE-693", "owasp": "M9:2023",
                "evidence": f"{s.get('layout_count',0)} layouts, "
                            f"{s.get('res_total_files',0)} res files, "
                            f"{s.get('res_size_mb',0)}MB",
                "remediation": "Good. R8 resource shrinking active."}
    return None


def rule_no_shrink(s):
    ratio = s.get("short_layout_ratio_pct", -1)
    if ratio < 0 or ratio >= 20: return None
    return {"name": f"Resources unshrunk ({ratio}% short layouts)",
            "severity": "LOW",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": f"{s.get('layout_count',0)} layouts, "
                        f"{s.get('res_total_files',0)} res files",
            "remediation": "Enable R8 shrinkResources (shrinkResources true + "
                           "minifyEnabled true). Removes unused drawables / layouts "
                           "from APK. Reduces app size (faster Play install) + reveals "
                           "less attack-surface metadata (unused screen names hint at "
                           "internal features)."}


def rule_oversized_res(s):
    size = s.get("res_size_mb", 0)
    if size < 50: return None
    return {"name": f"Large res/ bundle: {size}MB — possible bloat",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": f"res/: {s.get('res_total_files',0)} files, {size}MB total",
            "remediation": "Large resource bundles increase APK download size + RAM. "
                           "Consider Play Asset Delivery for large drawables. Use "
                           "vector drawables instead of multiple PNG densities. "
                           "Audit res/drawable-* for forgotten assets."}


RESOURCE_ID_OBFUSCATION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_no_shrink,
    rule_oversized_res,
]
