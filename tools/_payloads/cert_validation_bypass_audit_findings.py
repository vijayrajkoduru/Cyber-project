"""cert_validation_bypass_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("cert_validation_bypass_audit_total"):
        return None
    return {"name": "Certificate validation: no bypass patterns",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned with 5 bypass-pattern rules",
            "remediation": "Continue using the default TrustManager + system CA store. For high-value flows add certificate pinning.",
            "cwe": "CWE-295", "owasp": "M10:2023"}


def rule_bypass_detected(s):
    hits = s.get("cert_validation_bypass_hits") or {}
    if not hits:
        return None
    return {"name": f"{len(hits)} cert-validation bypass pattern(s) found",
            "severity": "CRITICAL", "cvss": "8.5",
            "cwe": "CWE-295", "owasp": "M10:2023",
            "evidence": "; ".join(f"{label}: {len(files)} file(s)" for label, files in list(hits.items())[:5]),
            "remediation": "Remove TrustAllX509TrustManager / empty checkServerTrusted / ALLOW_ALL_HOSTNAME_VERIFIER. These disable TLS entirely - attacker on the same Wi-Fi gets full MITM."}


CERT_VALIDATION_BYPASS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_bypass_detected,
]
