"""insecure_prng_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("insecure_prng_audit_total"):
        return None
    return {"name": "Insecure PRNG audit: clean (no Random/Math.random in security contexts)",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned; SecureRandom callers: {len(s.get('secure_prng_files', []))}",
            "remediation": "Continue using java.security.SecureRandom for all keys, IVs, nonces, and session tokens.",
            "cwe": "CWE-338", "owasp": "M10:2023"}


def rule_insecure_in_security_context(s):
    susp = s.get("security_context_insecure") or []
    if not susp:
        return None
    return {"name": f"java.util.Random / Math.random() used in {len(susp)} security-named class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-338", "owasp": "M10:2023",
            "evidence": "Callers: " + ", ".join(susp[:5]),
            "remediation": "Replace with java.security.SecureRandom. LCG-based Random is predictable and trivially brute-forced after ~624 outputs (Mersenne Twister state recovery)."}


def rule_general_insecure_prng(s):
    files = s.get("insecure_prng_files") or []
    if not files or s.get("security_context_insecure"):
        return None
    return {"name": f"java.util.Random / Math.random() used in {len(files)} class(es)",
            "severity": "INFO",
            "cwe": "CWE-338", "owasp": "M10:2023",
            "evidence": "Callers: " + ", ".join(files[:5]),
            "remediation": "Review each use. Non-security uses (e.g. UI animation) are OK. For any token/key/nonce/session — switch to SecureRandom."}


INSECURE_PRNG_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_insecure_in_security_context,
    rule_general_insecure_prng,
]
