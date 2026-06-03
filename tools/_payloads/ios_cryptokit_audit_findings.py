"""ios_cryptokit_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ios_cryptokit_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - CryptoKit audit N/A",
                "severity": "POSITIVE",
                "evidence": "No iOS source files",
                "remediation": "Run only against .ipa.",
                "cwe": "CWE-310", "owasp": "M10:2023"}
    return {"name": "iOS crypto API choice modern",
            "severity": "POSITIVE",
            "evidence": (f"CryptoKit users={len(s.get('cryptokit_users') or [])} "
                         f"CommonCrypto={len(s.get('commoncrypto_users') or [])}"),
            "remediation": "Continue preferring CryptoKit for new code.",
            "cwe": "CWE-310", "owasp": "M10:2023"}


def rule_legacy_only(s):
    if not s.get("is_ios"):
        return None
    if s.get("cryptokit_users"):
        return None
    cc = s.get("commoncrypto_users") or []
    if not cc:
        return None
    return {"name": f"Legacy CommonCrypto in {len(cc)} class(es); no CryptoKit migration",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-310", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(cc[:6]),
            "remediation": ("Migrate AES / SHA / HMAC / Curve25519 to CryptoKit (iOS 13+). "
                            "AES.GCM.seal / SymmetricKey / Curve25519.KeyAgreement.PrivateKey are "
                            "constant-time + memory-safe + harder to misuse.")}


IOS_CRYPTOKIT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_legacy_only]
