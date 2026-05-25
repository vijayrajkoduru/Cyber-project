"""play_integrity_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("play_integrity_audit_total"):
        return None
    return {"name": "NO device-attestation (Play Integrity / SafetyNet / Hardware Key Attestation)",
            "severity": "HIGH", "cvss": "6.0",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned - no IntegrityManager / SafetyNet / KeyAttestation markers",
            "remediation": "Add Play Integrity API. Server-side verify the JWT response includes 'MEETS_DEVICE_INTEGRITY' + 'MEETS_BASIC_INTEGRITY'. This is the ONLY anti-tamper that survives client bypass."}


def rule_modern_attestation(s):
    if not s.get("has_play_integrity"):
        return None
    return {"name": "Modern Play Integrity API in use",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M8:2023",
            "evidence": "IntegrityManager / IntegrityTokenRequest markers found - app uses current attestation API",
            "remediation": "Continue server-side validation. Verify the JWT signature against Google's public keys + check the integrity verdict on every sensitive request."}


def rule_deprecated_safetynet_only(s):
    if not (s.get("has_deprecated_safetynet") and not s.get("has_play_integrity")):
        return None
    return {"name": "Uses deprecated SafetyNet Attestation (EOL: 2024)",
            "severity": "HIGH", "cvss": "6.0",
            "cwe": "CWE-1104", "owasp": "M8:2023",
            "evidence": "SafetyNetClient markers but no Play Integrity migration found",
            "remediation": "URGENT migration: SafetyNet Attestation API was deprecated 2023, fully retired by end of 2024. Move to com.google.android.play.core.integrity.IntegrityManager."}


PLAY_INTEGRITY_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_modern_attestation,
    rule_deprecated_safetynet_only,
]
