"""wallet_misconfig_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("wallet_misconfig_audit_total"):
        return None
    return {"name": "Mobile wallet posture clean or absent",
            "severity": "POSITIVE",
            "evidence": (f"Apple Pay={len(s.get('apple_pay_users') or [])} "
                         f"Google Wallet={len(s.get('google_wallet_users') or [])} "
                         f"Samsung Pay={len(s.get('samsung_pay_users') or [])}"),
            "remediation": "Continue keeping merchant identifiers in backend / Apple Developer entitlements only.",
            "cwe": "CWE-200", "owasp": "M9:2023"}


def rule_hardcoded_merchant(s):
    mi = s.get("hardcoded_merchant_ids") or []
    if not mi: return None
    return {"name": f"{len(mi)} merchant identifier(s) hardcoded in binary",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "IDs: " + ", ".join(mi[:6]),
            "remediation": "Move merchant IDs to remote config / entitlements. Hardcoded values aid social-engineering chargeback fraud."}


WALLET_MISCONFIG_AUDIT_FINDING_RULES = [rule_positive_emit, rule_hardcoded_merchant]
