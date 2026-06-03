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
    return {"name": "Google Play Billing without server-side purchaseToken verification",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-345", "owasp": "M3:2023",
            "evidence": f"BillingClient users: {', '.join((s.get('billing_users') or [])[:6])}",
            "remediation": "Forward purchaseToken to backend; backend calls androidpublisher.purchases.subscriptionsv2.get / .acknowledge to verify. Client-only verification is replay-vulnerable."}


PLAY_BILLING_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_server_verify]
