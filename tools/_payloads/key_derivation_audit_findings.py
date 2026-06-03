"""key_derivation_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("key_derivation_audit_total"):
        return None
    return {"name": "KDF iteration counts at or above OWASP floor",
            "severity": "POSITIVE",
            "evidence": (f"PBKDF2 users={len(s.get('pbkdf2_users') or [])} "
                         f"scrypt={len(s.get('scrypt_users') or [])} "
                         f"argon2={len(s.get('argon2_users') or [])}"),
            "remediation": "Continue using PBKDF2 >= 600k (SHA-256) or argon2id m=64MiB t=3.",
            "cwe": "CWE-916", "owasp": "M10:2023"}


def rule_low_iterations(s):
    lows = s.get("low_iteration_files") or []
    if not lows:
        return None
    sample = ", ".join(f"{e['file']}:{e['iterations']}" for e in lows[:4])
    return {"name": f"PBKDF2 iteration count below 100k in {len(lows)} file(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-916", "owasp": "M10:2023",
            "evidence": f"Found: {sample}",
            "remediation": ("Raise PBKDF2 iterations to 600,000+ (OWASP 2023). Better: switch to "
                            "argon2id (m=64MiB, t=3, p=4) or scrypt (N=2^17, r=8, p=1).")}


def rule_pbkdf2_uncertain(s):
    if s.get("low_iteration_files") or s.get("scrypt_users") or s.get("argon2_users"):
        return None
    pb = s.get("pbkdf2_users") or []
    if not pb:
        return None
    return {"name": f"PBKDF2 used in {len(pb)} file(s); iteration count not detected",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-916", "owasp": "M10:2023",
            "evidence": f"Users: {', '.join(pb[:6])}",
            "remediation": "Manually verify iteration count >= 600,000 or migrate to argon2id."}


KEY_DERIVATION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_low_iterations, rule_pbkdf2_uncertain]
