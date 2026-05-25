"""hardcoded_keys_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("hardcoded_keys_audit_total"):
        return None
    return {"name": "No hardcoded encryption keys or high-entropy literals detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned with entropy + regex heuristics",
            "remediation": "Continue deriving keys at runtime (KeyGenerator + Android Keystore-backed key).",
            "cwe": "CWE-321", "owasp": "M10:2023"}


def rule_api_confirmed_keys(s):
    matched = s.get("matched_hardcoded_keys") or []
    if not matched:
        return None
    return {"name": f"{len(matched)} hardcoded key(s) passed directly to SecretKeySpec / IvParameterSpec / KeyGenerator",
            "severity": "CRITICAL", "cvss": "8.5",
            "cwe": "CWE-321", "owasp": "M10:2023",
            "evidence": "; ".join(f"{m['file']} {m['label']}: {m['value_preview']}" for m in matched[:3]),
            "remediation": "Move keys to Android Keystore (KeyGenParameterSpec.Builder().setIsStrongBoxBacked(true)). Hardcoded keys = full encryption bypass once an attacker decompiles the APK."}


def rule_high_entropy_hex(s):
    hits = s.get("high_entropy_hex_keys") or []
    if not hits:
        return None
    return {"name": f"{len(hits)} high-entropy hex literal(s) of crypto-key length",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-321", "owasp": "M10:2023",
            "evidence": "; ".join(f"{h['file']}: {h['value_preview']} (len {h['length']})" for h in hits[:3]),
            "remediation": "Inspect each literal manually. AES-128 / 192 / 256 keys in hex = 32 / 48 / 64 chars. Anything matching = candidate for key extraction."}


HARDCODED_KEYS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_api_confirmed_keys,
    rule_high_entropy_hex,
]
