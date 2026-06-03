"""ecdh_curve_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ecdh_curve_audit_total"):
        return None
    return {"name": "Key-agreement curves at modern strength",
            "severity": "POSITIVE",
            "evidence": (f"ECDH users={len(s.get('ecdh_users') or [])} "
                         f"DH users={len(s.get('dh_users') or [])} "
                         f"X25519/Ed25519={s.get('modern_curve_callers', 0)}"),
            "remediation": "Continue preferring X25519 / X448 / secp256r1 for key agreement.",
            "cwe": "CWE-326", "owasp": "M10:2023"}


def rule_dh_too_small(s):
    sm = s.get("dh_too_small") or []
    if not sm:
        return None
    sample = ", ".join(f"{e['file']}:{e['bits']}b" for e in sm[:4])
    return {"name": f"DH key size below 2048 in {len(sm)} call(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": f"Found: {sample}",
            "remediation": "Raise to >= 2048-bit DH prime, or migrate to X25519 / ECDH-secp256r1 (faster, smaller, safer)."}


def rule_weak_ec(s):
    c = s.get("weak_curve_users") or []
    if not c or not (s.get("ecdh_users") or s.get("dh_users")):
        return None
    return {"name": f"Weak EC curve in {len(c)} key-agreement file(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-326", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(c[:6]),
            "remediation": "Replace secp160/192/224 with secp256r1 or X25519. < 256-bit curves provide < 128-bit security."}


ECDH_CURVE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_dh_too_small, rule_weak_ec]
