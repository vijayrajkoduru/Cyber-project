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
    # presence != vuln: Apple's verifyReceipt / App Store Server API call
    # legitimately runs on the backend (the client forwards the receipt/JWS),
    # so its absence from the .ipa is not proof of missing verification -> INFO.
    return {"name": "StoreKit IAP present; confirm Apple server-side receipt verification",
            "severity": "INFO",
            "cwe": "CWE-345", "owasp": "M3:2023",
            "evidence": (f"StoreKit users: {', '.join((s.get('storekit_users') or [])[:6])} "
                         "| No client-visible Apple verify endpoint; backend verification is out of scope "
                         "for static IPA analysis."),
            "remediation": "Verify the backend receives the receipt / JWS and calls Apple verifyReceipt (legacy) or App Store Server API (StoreKit2) to confirm authenticity + refund status. Client-side validation alone would be replay-vulnerable."}


STOREKIT_RECEIPT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_server_verify]
