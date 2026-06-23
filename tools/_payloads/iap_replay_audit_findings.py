"""iap_replay_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("iap_replay_audit_total"):
        return None
    return {"name": "IAP replay protection present or no IAP",
            "severity": "POSITIVE",
            "evidence": (f"transactionId users={len(s.get('transaction_id_users') or [])} "
                         f"dedup users={len(s.get('dedup_logic_users') or [])} "
                         f"nonce users={len(s.get('nonce_users') or [])}"),
            "remediation": "Continue persisting transactionId / nonce and rejecting reuse on the backend.",
            "cwe": "CWE-294", "owasp": "M3:2023"}


def rule_no_replay_protection(s):
    if not s.get("transaction_id_users") or s.get("dedup_logic_users") or s.get("nonce_users"):
        return None
    # presence != vuln: absence of a *client-side* dedup/nonce marker is not
    # proof of replay risk — replay protection legitimately lives on the
    # backend, which is out of scope for static APK/IPA analysis. INFO, not HIGH.
    return {"name": f"IAP transactionId used in {len(s.get('transaction_id_users') or [])} class(es); confirm server-side replay protection",
            "severity": "INFO",
            "cwe": "CWE-294", "owasp": "M3:2023",
            "evidence": ("Files: " + ", ".join((s.get('transaction_id_users') or [])[:6])
                         + " | No client-side dedup/nonce marker found; backend dedup is not visible to static analysis."),
            "remediation": "Verify the backend persists transactionId / orderId and rejects reuse. Bind purchase to appAccountToken (StoreKit2) or obfuscatedAccountId (Play Billing) to prevent cross-user replay."}


IAP_REPLAY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_replay_protection]
