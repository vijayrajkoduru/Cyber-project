"""dns_over_https_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("dns_over_https_audit_total"):
        return None
    return {"name": "DoH / DoT resolver evidence present",
            "severity": "POSITIVE",
            "evidence": f"DoH evidence files={len(s.get('doh_evidence_files') or [])}",
            "remediation": "Continue resolving sensitive endpoints via DoH/DoT; consider falling back to DNSSEC-validated resolvers.",
            "cwe": "CWE-345", "owasp": "M3:2023"}


def rule_no_doh(s):
    nc = s.get("network_client_files") or []
    if not nc:
        return None
    if s.get("doh_evidence_files"):
        return None
    return {"name": "No DoH / DoT resolver detected (default system DNS in use)",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-345", "owasp": "M3:2023",
            "evidence": f"{len(nc)} TLS-network client file(s); no DnsOverHttps / 1.1.1.1 / dns.google references",
            "remediation": ("Banking, secure messaging, and other privacy-sensitive apps should bypass "
                            "carrier DNS via OkHttp DnsOverHttps (Android) or NEDNSOverHTTPSSettings (iOS 14+). "
                            "Prevents on-path traffic analysis and DNS spoofing.")}


DNS_OVER_HTTPS_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_doh]
