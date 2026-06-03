"""password_hash_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("password_hash_audit_total"):
        return None
    return {"name": "No weak password hashing detected",
            "severity": "POSITIVE",
            "evidence": f"Strong hash users={s.get('strong_hash_users', 0)}; no MD5/SHA1 near password symbols",
            "remediation": "Continue using PBKDF2 / argon2id / scrypt for password hashing.",
            "cwe": "CWE-916", "owasp": "M10:2023"}


def rule_weak_hash_password(s):
    w = s.get("weak_hash_with_password") or []
    if not w:
        return None
    return {"name": f"MD5 / SHA1 hashing co-located with password symbols ({len(w)} file(s))",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-916", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(w[:6]),
            "remediation": ("Never hash passwords with MD5 / SHA1 - these are designed for speed. "
                            "Use PBKDF2 (>= 600k iter), argon2id (m=64MiB, t=3), or scrypt (N=2^17).")}


def rule_weak_hash_general(s):
    if s.get("weak_hash_with_password"):
        return None
    g = s.get("weak_hash_general") or []
    if not g:
        return None
    return {"name": f"MD5 / SHA1 usage ({len(g)} file(s)); not co-located with password symbols",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(g[:6]),
            "remediation": "Audit each call. MD5/SHA1 acceptable only for non-security checksums; replace with SHA-256 elsewhere."}


PASSWORD_HASH_AUDIT_FINDING_RULES = [rule_positive_emit, rule_weak_hash_password, rule_weak_hash_general]
