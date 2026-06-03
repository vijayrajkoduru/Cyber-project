"""kdf_salt_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("kdf_salt_audit_total"):
        return None
    return {"name": "KDF salts appear randomly generated",
            "severity": "POSITIVE",
            "evidence": (f"KDF users={len(s.get('kdf_users') or [])} "
                         f"SecureRandom + KDF co-usage={s.get('random_salt_co_usage', 0)}"),
            "remediation": "Continue generating per-record salt with SecureRandom.nextBytes(new byte[16]).",
            "cwe": "CWE-759", "owasp": "M10:2023"}


def rule_static_salt(s):
    f = s.get("static_salt_files") or []
    if not f:
        return None
    return {"name": f"Static / zero-byte salt in {len(f)} KDF call(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-759", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(f[:6]),
            "remediation": ("Per-record SecureRandom.nextBytes(new byte[16]) salt. Store salt + iterations "
                            "alongside the derived key. Static salts let one rainbow table crack all users.")}


def rule_no_random_salt(s):
    if s.get("static_salt_files"):
        return None
    if not s.get("kdf_users") or s.get("random_salt_co_usage", 0) > 0:
        return None
    return {"name": "KDF used without SecureRandom salt anywhere in module",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-759", "owasp": "M10:2023",
            "evidence": f"{len(s.get('kdf_users') or [])} KDF caller(s); no SecureRandom co-located",
            "remediation": "Manually verify salt provenance; ensure it's random and per-record, not derived from the password."}


KDF_SALT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_static_salt, rule_no_random_salt]
