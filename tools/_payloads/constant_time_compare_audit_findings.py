"""constant_time_compare_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("constant_time_compare_audit_total"):
        return None
    return {"name": "No timing-unsafe compares co-located with secrets",
            "severity": "POSITIVE",
            "evidence": f"Safe-compare users={s.get('safe_compare_users', 0)} / {s.get('files_scanned', 0)} files",
            "remediation": "Continue using MessageDigest.isEqual / CRYPTO_memcmp on HMAC and tag checks.",
            "cwe": "CWE-208", "owasp": "M10:2023"}


def rule_unsafe_compare(s):
    u = s.get("unsafe_compare_with_secret_keywords") or []
    if not u:
        return None
    return {"name": f"Timing-unsafe compare on secret in {len(u)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-208", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(u[:6]),
            "remediation": ("Replace String.equals / Arrays.equals / strcmp / memcmp with constant-time "
                            "MessageDigest.isEqual (Java) or CRYPTO_memcmp (Obj-C / BoringSSL). "
                            "Timing oracles let an attacker forge HMAC/tag values byte by byte.")}


CONSTANT_TIME_COMPARE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_unsafe_compare]
