"""certificate_transparency_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("certificate_transparency_audit_total"):
        return None
    return {"name": "Certificate Transparency posture clean",
            "severity": "POSITIVE",
            "evidence": (f"CT evidence files={len(s.get('ct_evidence_files') or [])} "
                         f"TLS clients={len(s.get('tls_client_files') or [])}"),
            "remediation": "Continue requiring CT (SCT) validation for production hosts.",
            "cwe": "CWE-296", "owasp": "M3:2023"}


def rule_no_ct(s):
    tls = s.get("tls_client_files") or []
    if not tls:
        return None
    if s.get("ct_evidence_files"):
        return None
    return {"name": "TLS clients present but no Certificate Transparency validation",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-296", "owasp": "M3:2023",
            "evidence": f"{len(tls)} TLS client file(s); no <certificate-transparency> in NSC and no NSRequiresCertificateTransparency in Info.plist",
            "remediation": ("Android: enable certificate-transparency via NSC + conscrypt. "
                            "iOS: set NSRequiresCertificateTransparency=true under your NSExceptionDomains entry "
                            "or globally in NSAppTransportSecurity. Detects rogue-CA issuance.")}


CERTIFICATE_TRANSPARENCY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_ct]
