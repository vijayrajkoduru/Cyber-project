"""accessibility_service_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("accessibility_service_audit_total", 0) > 0: return None
    return {"name": "No AccessibilityService declared",
            "severity": "POSITIVE",
            "cwe": "CWE-668", "owasp": "M8:2023",
            "evidence": "no BIND_ACCESSIBILITY_SERVICE in manifest",
            "remediation": "App doesn't request accessibility privileges — minimal "
                           "attack surface from this vector."}


def rule_a11y_present(s):
    services = s.get("accessibility_services") or []
    if not services: return None
    return {"name": f"AccessibilityService declared ({len(services)})",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-668", "owasp": "M8:2023",
            "evidence": " | ".join(s["name"] for s in services),
            "remediation": "AccessibilityService is the #1 banking-trojan vector. "
                           "If this is YOUR LEGITIMATE app (password manager, screen "
                           "reader, kiosk-mode automator): document the use case "
                           "prominently in Play Store description + first-run dialog "
                           "explaining what user data is accessed. Otherwise: REMOVE — "
                           "Google Play has strict policy on accessibility usage; "
                           "non-justified use → suspension. Test against Play Store "
                           "policy: support.google.com/googleplay/android-developer/"
                           "answer/14094618."}


ACCESSIBILITY_SERVICE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_a11y_present,
]
