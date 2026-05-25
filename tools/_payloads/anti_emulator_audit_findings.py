"""anti_emulator_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("anti_emulator_audit_total"):
        return None
    return {"name": "NO emulator detection - app runs identically on AVD/Genymotion",
            "severity": "LOW", "cvss": "3.0",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no Build.FINGERPRINT / MODEL / MANUFACTURER checks",
            "remediation": "If your threat model includes mass-scale bot abuse, add Build.FINGERPRINT.contains('generic')/('vbox') check + SensorManager.getSensorList().size() check. Combine with Play Integrity attestation server-side."}


def rule_emulator_detection_present(s):
    mechs = s.get("emulator_detection_mechanisms") or {}
    if not mechs:
        return None
    sev = "INFO" if len(mechs) >= 3 else "LOW"
    return {"name": f"Emulator detection: {len(mechs)} mechanism(s) found",
            "severity": sev, "cvss": "2.5",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "; ".join(mechs.keys()),
            "remediation": "All client-side emulator checks are bypassable with MagiskHide / Universal Hider. For high-value flows verify environment server-side via Play Integrity."}


ANTI_EMULATOR_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_emulator_detection_present,
]
