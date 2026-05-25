"""custom_crypto_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("custom_crypto_audit_total"):
        return None
    return {"name": "Custom crypto audit: no homebrew XOR loops or non-JCA encrypt methods",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "Continue delegating crypto to javax.crypto / java.security / BouncyCastle. Never roll your own.",
            "cwe": "CWE-327", "owasp": "M10:2023"}


def rule_xor_loops(s):
    xor = s.get("xor_loop_files") or []
    if not xor:
        return None
    return {"name": f"{len(xor)} class(es) contain heavy XOR loops (likely homebrew cipher)",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "; ".join(f"{x['file']} (xor-lit8: {x['xor_lit8']}, xor-int: {x['xor_int']})" for x in xor[:5]),
            "remediation": "XOR-with-fixed-byte is NOT encryption - reversible in seconds. Use Cipher.getInstance(\"AES/GCM/NoPadding\")."}


def rule_homebrew_methods(s):
    methods = s.get("homebrew_crypto_methods") or []
    if not methods:
        return None
    return {"name": f"{len(methods)} encrypt/decrypt method(s) bypass javax.crypto",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-327", "owasp": "M10:2023",
            "evidence": "Files: " + ", ".join(m["file"] for m in methods[:5]),
            "remediation": "Replace custom encrypt/decrypt methods with Cipher.getInstance() + KeyGenerator. Custom obfuscation is reverse-engineered routinely."}


CUSTOM_CRYPTO_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_xor_loops,
    rule_homebrew_methods,
]
