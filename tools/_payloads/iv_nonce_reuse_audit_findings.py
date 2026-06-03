"""iv_nonce_reuse_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("iv_nonce_reuse_audit_total"):
        return None
    return {"name": "IV / nonce derivation appears random",
            "severity": "POSITIVE",
            "evidence": f"SecureRandom + Cipher co-usage: {s.get('secure_random_co_usage', 0)} file(s)",
            "remediation": "Continue deriving IVs via SecureRandom.nextBytes(); never reuse a GCM nonce.",
            "cwe": "CWE-329", "owasp": "M10:2023"}


def rule_literal_or_zero_iv(s):
    lits = s.get("literal_iv_files") or []
    zeros = s.get("zero_iv_files") or []
    if not (lits or zeros):
        return None
    return {"name": f"Hardcoded / zero-byte IV in {len(lits) + len(zeros)} class(es)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-329", "owasp": "M10:2023",
            "evidence": f"Literal IV: {', '.join(lits[:4])} | Zero IV: {', '.join(zeros[:4])}",
            "remediation": ("Generate IV with SecureRandom.nextBytes(new byte[12]) for GCM or new byte[16] "
                            "for CBC. Prepend IV to ciphertext. A reused GCM nonce voids confidentiality "
                            "AND authenticity (attacker can forge ciphertexts).")}


IV_NONCE_REUSE_AUDIT_FINDING_RULES = [rule_positive_emit, rule_literal_or_zero_iv]
