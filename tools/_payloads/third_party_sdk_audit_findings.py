"""third_party_sdk_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("third_party_sdk_audit_total"):
        return None
    return {"name": "SDK audit: no third-party tracking SDKs detected",
            "severity": "POSITIVE",
            "evidence": "Package tree scanned — no known analytics/ad/tracking SDKs bundled",
            "remediation": "Minimal SDK footprint — good for user privacy + faster startup.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_high_risk_sdks(s):
    high = s.get("high_risk_sdks") or []
    if not high:
        return None
    return {"name": f"{len(high)} high-risk tracking SDK(s) bundled",
            "severity": "HIGH", "cvss": "6.5",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "; ".join(f"{h['sdk']}: {h['description']}" for h in high[:5]),
            "remediation": "Audit user-consent flows for each SDK. Required for GDPR / CCPA compliance. Document data sharing in privacy policy."}


def rule_total_sdks(s):
    total = s.get("third_party_sdk_audit_total", 0)
    if total < 5:
        return None
    return {"name": f"{total} third-party SDKs detected — high supply-chain attack surface",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-1357", "owasp": "M3:2023",
            "evidence": f"Total SDKs: {total}. Each adds CVE exposure + binary size + permissions.",
            "remediation": "Audit each SDK for necessity. Subscribe to CVE alerts per SDK. Consider replacing with first-party code."}


THIRD_PARTY_SDK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_high_risk_sdks,
    rule_total_sdks,
]
