"""weak_crypto_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("weak_crypto_audit_total"):
        return None
    return {"name": "Crypto audit: no deprecated primitives or insecure modes",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} files scanned with 9 crypto patterns — no matches",
            "remediation": "Continue using AES-GCM, SHA-256+, hardware-backed keystore.",
            "cwe": "CWE-327", "owasp": "M6:2023"}


def rule_deprecated_ciphers(s):
    hits = s.get("crypto_issues") or []
    bad_ciphers = [h for h in hits if h["kind"] in ("DES cipher", "RC4 cipher", "Blowfish cipher", "AES ECB mode")]
    if not bad_ciphers:
        return None
    return {"name": f"{len(bad_ciphers)} deprecated cipher usage(s)",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-327", "owasp": "M6:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in bad_ciphers[:5]),
            "remediation": "Replace with AES-GCM-256. DES/RC4 are broken. ECB mode reveals data patterns."}


def rule_weak_hash(s):
    hits = s.get("crypto_issues") or []
    weak_hash = [h for h in hits if h["kind"] in ("MD5 used for crypto", "SHA1 used for crypto")]
    if not weak_hash:
        return None
    return {"name": f"{len(weak_hash)} weak hash function usage(s)",
            "severity": "MEDIUM", "cvss": "5.9",
            "cwe": "CWE-328", "owasp": "M6:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in weak_hash[:5]),
            "remediation": "Use SHA-256+ for hashing. For password hashing, use bcrypt/scrypt/Argon2 — never raw SHA."}


def rule_tls_bypass(s):
    hits = s.get("crypto_issues") or []
    bypass = [h for h in hits if h["kind"] in ("TrustManager bypass", "HostnameVerifier ALLOW_ALL")]
    if not bypass:
        return None
    return {"name": f"{len(bypass)} TLS validation bypass(es) detected",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-295", "owasp": "M5:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in bypass[:5]),
            "remediation": "REMOVE bypass code. Use Android's default TLS validation. Add cert-pinning for production."}


WEAK_CRYPTO_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_deprecated_ciphers,
    rule_weak_hash,
    rule_tls_bypass,
]
