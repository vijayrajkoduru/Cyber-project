"""rsa_key_size_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("rsa_key_size_audit_total"):
        return None
    return {"name": "Key sizes meet NIST / OWASP 2023 floors",
            "severity": "POSITIVE",
            "evidence": (f"RSA callers={len(s.get('rsa_callers') or [])} "
                         f"ECDSA callers={len(s.get('ec_callers') or [])} "
                         "no sub-2048 RSA or weak curves detected"),
            "remediation": "Continue using RSA >= 2048 (3072 for >2030 lifespan) or secp256r1 / Ed25519.",
            "cwe": "CWE-326", "owasp": "M10:2023"}


def rule_rsa_too_small(s):
    rs = s.get("rsa_too_small") or []
    if not rs:
        return None
    sample = ", ".join(f"{e['file']}:{e['bits']}b" for e in rs[:4])
    return {"name": f"RSA key size below 2048 in {len(rs)} file(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": f"Found: {sample}",
            "remediation": "Raise to >= 2048 bits (3072 preferred for keys outliving 2030)."}


def rule_weak_curve(s):
    c = s.get("weak_curve_users") or []
    if not c:
        return None
    return {"name": f"Weak / deprecated EC curve in {len(c)} file(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": f"Files: {', '.join(c[:6])} (secp160/192/224 or secp192k1)",
            "remediation": "Replace with secp256r1 (P-256) or Ed25519. Curve25519 / Ed25519 preferred for new code."}


RSA_KEY_SIZE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_rsa_too_small, rule_weak_curve]
