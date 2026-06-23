"""weak_crypto_audit — findings rules.

Zero-FP: "presence != usage". A primitive matched inside a bundled SDK /
library or a test path is NOT proof the APP uses weak crypto. Hits carry an
`app_code` flag (set by the scanner): only app-code hits are graded;
library-only / test-only hits are reported at INFO for awareness.
"""


def _app(hits, kinds):
    return [h for h in hits if h.get("kind") in kinds and h.get("app_code", True)]


def _lib(hits, kinds):
    return [h for h in hits if h.get("kind") in kinds and not h.get("app_code", True)]


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
    kinds = ("DES cipher", "RC4 cipher", "Blowfish cipher", "AES ECB mode")
    bad_ciphers = _app(hits, kinds)
    if not bad_ciphers:
        return None
    return {"name": f"{len(bad_ciphers)} deprecated cipher usage(s) in app code",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-327", "owasp": "M6:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in bad_ciphers[:5]),
            "remediation": "Replace with AES-GCM-256. DES/RC4 are broken. ECB mode reveals data patterns."}


def rule_weak_hash(s):
    hits = s.get("crypto_issues") or []
    kinds = ("MD5 used for crypto", "SHA1 used for crypto")
    weak_hash = _app(hits, kinds)
    if not weak_hash:
        return None
    return {"name": f"{len(weak_hash)} weak hash function usage(s) in app code",
            "severity": "MEDIUM", "cvss": "5.9",
            "cwe": "CWE-328", "owasp": "M6:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in weak_hash[:5]),
            "remediation": "Use SHA-256+ for hashing. For password hashing, use bcrypt/scrypt/Argon2 — never raw SHA."}


def rule_tls_bypass(s):
    hits = s.get("crypto_issues") or []
    kinds = ("TrustManager bypass", "HostnameVerifier ALLOW_ALL")
    bypass = _app(hits, kinds)
    if not bypass:
        return None
    return {"name": f"{len(bypass)} TLS validation bypass(es) in app code",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-295", "owasp": "M5:2023",
            "evidence": "; ".join(f"{h['kind']} in {h['file']}" for h in bypass[:5]),
            "remediation": "REMOVE bypass code. Use Android's default TLS validation. Add cert-pinning for production."}


def rule_library_only(s):
    """Weak primitives / bypasses found ONLY inside bundled SDKs or test paths.
    Reported for awareness, not graded — the app does not control library code."""
    hits = s.get("crypto_issues") or []
    all_kinds = ("DES cipher", "RC4 cipher", "Blowfish cipher", "AES ECB mode",
                 "MD5 used for crypto", "SHA1 used for crypto",
                 "TrustManager bypass", "HostnameVerifier ALLOW_ALL")
    lib = _lib(hits, all_kinds)
    app = _app(hits, all_kinds)
    if not lib or app:
        return None
    seen = sorted({h["kind"] for h in lib})
    return {"name": f"Weak crypto patterns present only in bundled libraries/test code ({len(lib)} match(es))",
            "severity": "INFO",
            "cwe": "CWE-327", "owasp": "M6:2023",
            "evidence": "Library/test paths: " + "; ".join(f"{h['kind']} in {h['file']}" for h in lib[:5]) + f" | kinds: {', '.join(seen)}",
            "remediation": "These references live in 3rd-party SDKs or test/mock code, not the app's own crypto path. No action unless the app explicitly invokes the weak primitive through the SDK."}


WEAK_CRYPTO_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_deprecated_ciphers,
    rule_weak_hash,
    rule_tls_bypass,
    rule_library_only,
]
