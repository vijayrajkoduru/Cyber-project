"""storekit_receipt_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("storekit_receipt_audit_total"):
        return None
    if not s.get("is_ios"):
        return {"name": "Not an iOS bundle - StoreKit N/A",
                "severity": "POSITIVE", "evidence": "No iOS sources",
                "remediation": "Run only against .ipa.",
                "cwe": "CWE-345", "owasp": "M3:2023"}
    return {"name": "StoreKit receipt validation appears server-side",
            "severity": "POSITIVE",
            "evidence": f"StoreKit users={len(s.get('storekit_users') or [])} | Apple verify endpoints={len(s.get('server_validate_endpoints') or [])}",
            "remediation": "Continue verifying receipts via Apple verifyReceipt / StoreKit2 JWS on YOUR backend.",
            "cwe": "CWE-345", "owasp": "M3:2023"}


def rule_no_server_verify(s):
    if not s.get("is_ios"): return None
    if not s.get("storekit_users") or s.get("server_validate_endpoints"): return None
    return {"name": "StoreKit IAP without Apple server-side receipt verification",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-345", "owasp": "M3:2023",
            "evidence": f"StoreKit users: {', '.join((s.get('storekit_users') or [])[:6])}",
            "remediation": "Forward receipt / JWS to your backend; backend calls Apple verifyReceipt (legacy) or App Store Server API (StoreKit2) to confirm authenticity + check refund status. Client-side validation alone is replay-vulnerable."}


STOREKIT_RECEIPT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_server_verify]
