"""broadcast_receiver_exposed_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("broadcast_receiver_exposed_audit_total", 0) > 0: return None
    total = len(s.get("all_receivers") or [])
    return {"name": f"All {total} BroadcastReceiver(s) properly protected",
            "severity": "POSITIVE",
            "cwe": "CWE-925", "owasp": "M3:2023",
            "evidence": f"{total} receivers, 0 risky-exported-no-perm",
            "remediation": "Maintain. New receivers should use signature-level "
                           "permission or android:exported='false' explicitly."}


def rule_risky_receivers(s):
    risky = s.get("risky_receivers") or []
    if not risky: return None
    sample = " | ".join(
        f"{r['name']} (actions: {','.join(r['actions'][:2])})" for r in risky[:3]
    )
    return {"name": f"{len(risky)} BroadcastReceiver(s) exported without permission",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-925", "owasp": "M3:2023",
            "evidence": sample,
            "remediation": "Any installed app can broadcast intents matching these "
                           "filters. (1) Set android:exported='false' if internal-only, "
                           "(2) Add android:permission='YourApp.SENSITIVE_BROADCAST' "
                           "with signature-level grant for trusted callers, "
                           "(3) Verify caller UID in onReceive() via Binder.getCallingUid()."}
