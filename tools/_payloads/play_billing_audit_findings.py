"""play_billing_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("play_billing_audit_total"):
        return None
    return {"name": "Play Billing posture appears server-verified",
            "severity": "POSITIVE",
            "evidence": (f"BillingClient users={len(s.get('billing_users') or [])} "
                         f"server-API refs={len(s.get('server_api_references') or [])} "
                         f"purchaseToken forwarders={s.get('purchase_token_forwarders', 0)}"),
            "remediation": "Continue verifying purchaseToken via Google Play Developer API on your backend.",
            "cwe": "CWE-345", "owasp": "M3:2023"}


def rule_no_server_verify(s):
    if not s.get("billing_users") or s.get("server_api_references"):
        return None
    if s.get("purchase_token_forwarders", 0) > 0: return None
    # presence != vuln: the Play Developer API call legitimately runs on the
    # backend and won't appear in the client APK. Not seeing it client-side is
    # not proof of missing verification -> INFO, not HIGH.
    return {"name": "Google Play Billing present; confirm server-side purchaseToken verification",
            "severity": "INFO",
            "cwe": "CWE-345", "owasp": "M3:2023",
            "evidence": (f"BillingClient users: {', '.join((s.get('billing_users') or [])[:6])} "
                         "| No client-visible Play Developer API call or purchaseToken forwarder; backend "
                         "verification is out of scope for static APK analysis."),
            "remediation": "Verify the backend forwards purchaseToken and calls androidpublisher.purchases.subscriptionsv2.get / .acknowledge. Client-only verification would be replay-vulnerable."}


PLAY_BILLING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_server_verify]
