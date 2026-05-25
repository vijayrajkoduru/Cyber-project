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
    """Always emit a count finding when ANY SDKs are detected.
    Severity scales with count: 1-4 = INFO, 5-9 = MEDIUM, 10+ = HIGH.
    Without this, Section 18 (Third-Party SDK Audit) was empty when 1-4
    benign SDKs were present and rule_high_risk_sdks didn't fire."""
    total = s.get("third_party_sdk_audit_total", 0)
    if total <= 0:
        return None
    if total >= 10:
        sev, cvss = "HIGH", "6.5"
    elif total >= 5:
        sev, cvss = "MEDIUM", "5.0"
    else:
        sev, cvss = "INFO", "2.0"
    return {"name": f"{total} third-party SDK(s) detected - supply-chain attack surface",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-1357", "owasp": "M3:2023",
            "evidence": f"Total SDKs: {total}. Each adds CVE exposure + binary size + permissions.",
            "remediation": "Audit each SDK for necessity. Subscribe to CVE alerts per SDK. Consider replacing with first-party code."}


THIRD_PARTY_SDK_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_high_risk_sdks,
    rule_total_sdks,
]
