"""anti_root_detection_static — findings rules."""


def rule_positive_emit(s):
    n = s.get("anti_root_detection_static_total", 0)
    if n > 0:
        return None
    return {"name": "Anti-root / anti-jailbreak detection NOT present",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, "
                        "found 0 known root-detection markers",
            "remediation": "For apps in finance / health / DRM verticals, integrate "
                           "a runtime root/jailbreak detection library (RootBeer for "
                           "Android, IOSSecuritySuite for iOS) + Google Play Integrity API. "
                           "Detection-only is bypassable but raises the attack bar."}


def rule_root_detection_present(s):
    n = s.get("anti_root_detection_static_total", 0)
    if n == 0: return None
    sample = s.get("root_detection_markers_found", [])[:5]
    return {"name": f"Anti-root detection present ({n} marker(s))",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": "markers: " + ", ".join(m["marker"] for m in sample),
            "remediation": "Good. Continue monitoring detection-evasion advisories "
                           "and update detection libraries regularly. Add Play Integrity "
                           "/ App Attest server-side verification as defense in depth."}


ANTI_ROOT_DETECTION_STATIC_FINDING_RULES = [
    rule_positive_emit,
    rule_root_detection_present,
]
