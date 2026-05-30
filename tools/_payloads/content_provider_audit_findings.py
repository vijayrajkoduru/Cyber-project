"""content_provider_audit — findings rules."""


def rule_positive_emit(s):
    risky = s.get("risky_providers") or []
    if risky: return None
    total = len(s.get("all_providers") or [])
    return {"name": f"All {total} ContentProvider(s) properly permission-gated",
            "severity": "POSITIVE",
            "cwe": "CWE-926", "owasp": "M3:2023",
            "evidence": f"{total} providers, 0 risky-exported",
            "remediation": "Maintain. Continue to require permission for any newly-added providers."}


def rule_risky_provider(s):
    risky = s.get("risky_providers") or []
    if not risky: return None
    n = len(risky)
    sample = " | ".join(f"{p['authority']} ({p['name']})" for p in risky[:5])
    return {"name": f"{n} ContentProvider(s) exported WITHOUT permission",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-926", "owasp": "M3:2023",
            "evidence": sample,
            "remediation": "Either: (1) set android:exported='false' if no external "
                           "app needs access, (2) add android:readPermission + "
                           "android:writePermission with signature-level perms for "
                           "trusted callers, or (3) implement explicit caller-UID "
                           "checks in your provider methods. Default-exposed providers "
                           "= classic data-leak (SQLite query via content:// URI by "
                           "any app on device)."}
