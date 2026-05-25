"""ios_jailbreak_detection_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("ios_jailbreak_detection_audit_total"):
        return None
    if not s.get("binaries_scanned"):
        return {"name": "No Mach-O binaries - not an IPA upload",
                "severity": "POSITIVE",
                "evidence": "Upload is likely an APK / non-iOS binary",
                "remediation": "No action required.",
                "cwe": "CWE-200", "owasp": "M8:2023"}
    return {"name": "iOS app has NO jailbreak detection",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('binaries_scanned', 0)} Mach-O binaries scanned - no /Applications/Cydia / apt path / fork / dyld checks",
            "remediation": "Add jailbreak detection via stat(/Applications/Cydia.app), fork() (returns >=0 only on jailbroken), and dyld_get_image_name() walk for MobileSubstrate. Bypassable by Liberty Lite, but raises the attacker's effort floor."}


def rule_jailbreak_detection_present(s):
    mechs = s.get("jailbreak_mechanisms") or {}
    if not mechs:
        return None
    return {"name": f"iOS jailbreak detection: {len(mechs)} mechanism(s)",
            "severity": "INFO",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "; ".join(mechs.keys()),
            "remediation": "All standalone client checks are bypassable with Liberty Lite / A-Bypass / Frida ssl-kill-switch-2. For real protection: server-side environment attestation via DeviceCheck or App Attest."}


IOS_JAILBREAK_DETECTION_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_jailbreak_detection_present,
]
