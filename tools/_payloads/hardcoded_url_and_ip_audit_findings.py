"""hardcoded_url_and_ip_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("hardcoded_url_and_ip_audit_total"):
        return None
    return {"name": "Endpoint hygiene: no cleartext URLs or internal IPs found",
            "severity": "POSITIVE",
            "evidence": "Decompiled tree scanned — no http:// URLs or RFC1918 IPs",
            "remediation": "Continue using HTTPS-only endpoints + BuildConfig-injected staging URLs.",
            "cwe": "CWE-319", "owasp": "M5:2023"}


def rule_cleartext_urls(s):
    urls = s.get("cleartext_urls") or []
    if not urls:
        return None
    return {"name": f"{len(urls)} cleartext (http://) URL(s) embedded in code",
            "severity": "HIGH", "cvss": "7.4",
            "cwe": "CWE-319", "owasp": "M5:2023",
            "evidence": "; ".join(urls[:5]),
            "remediation": "Migrate all listed endpoints to HTTPS. Cleartext traffic is sniffable on hostile Wi-Fi."}


def rule_internal_ips(s):
    ips = s.get("internal_ips") or []
    if not ips:
        return None
    return {"name": f"{len(ips)} internal/RFC1918 IP(s) hardcoded",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "; ".join(ips[:8]),
            "remediation": "Move internal endpoint addresses to BuildConfig (debug-only) or remove from release builds."}


HARDCODED_URL_AND_IP_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_cleartext_urls,
    rule_internal_ips,
]
