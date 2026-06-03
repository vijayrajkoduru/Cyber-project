"""mutual_tls_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("mutual_tls_audit_total"):
        return None
    return {"name": "mTLS posture clean or not in use",
            "severity": "POSITIVE",
            "evidence": (f"mTLS callers={len(s.get('mtls_callers') or [])} "
                         f"P12 resources={len(s.get('p12_resources') or [])} "
                         f"KeyStore-backed={s.get('keystore_backed_callers', 0)}"),
            "remediation": "Continue storing client keys in AndroidKeyStore / iOS Keychain - never in res/assets.",
            "cwe": "CWE-321", "owasp": "M10:2023"}


def rule_p12_resource(s):
    p12 = s.get("p12_resources") or []
    if not p12:
        return None
    return {"name": f"{len(p12)} PKCS12 / .p12 file(s) bundled in app resources",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-321", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(p12[:6]),
            "remediation": ("Private key + cert shipped in res/assets is recoverable via `apktool d`. "
                            "Move provisioning to per-device pairing flow + AndroidKeyStore / Keychain.")}


def rule_no_keystore_backing(s):
    if s.get("p12_resources"):
        return None
    if not s.get("mtls_callers") or s.get("keystore_backed_callers", 0) > 0:
        return None
    return {"name": f"mTLS callers ({len(s.get('mtls_callers') or [])}) without KeyStore / Keychain backing",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-321", "owasp": "M10:2023",
            "evidence": "No AndroidKeyStore / kSecAttrAccessible* references near mTLS callers",
            "remediation": "Generate / import client cert into AndroidKeyStore (hardware-backed when available) and reference by alias."}


MUTUAL_TLS_AUDIT_FINDING_RULES = [rule_positive_emit, rule_p12_resource, rule_no_keystore_backing]
