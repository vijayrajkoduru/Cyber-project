"""aes_ecb_mode_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("aes_ecb_mode_audit_total"):
        return None
    if s.get("gcm_files"):
        return {"name": "AES/GCM (authenticated encryption) in use, no ECB",
                "severity": "POSITIVE",
                "evidence": f"GCM in {len(s.get('gcm_files', []))} file(s); ECB in 0 files",
                "remediation": "Continue using AES/GCM/NoPadding. Rotate keys via Android Keystore.",
                "cwe": "CWE-327", "owasp": "M10:2023"}
    return {"name": "No AES/ECB or CBC/NoPadding patterns",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "Continue. Verify any AES usage specifies GCM mode explicitly.",
            "cwe": "CWE-327", "owasp": "M10:2023"}


def rule_ecb_usage(s):
    ecb = s.get("ecb_files") or []
    if not ecb:
        return None
    return {"name": f"AES/ECB mode used in {len(ecb)} file(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "Callers: " + ", ".join(ecb[:5]),
            "remediation": "Replace AES/ECB with AES/GCM/NoPadding (auth-encrypt). ECB leaks plaintext patterns (ECB-penguin)."}


AES_ECB_MODE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_ecb_usage,
]
