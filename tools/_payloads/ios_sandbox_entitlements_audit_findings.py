"""ios_sandbox_entitlements_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("ios_sandbox_entitlements_audit_total", 0) > 0: return None
    if not s.get("entitlement_sources"):
        return {"name": "Not iOS / no entitlements file present",
                "severity": "POSITIVE", "cwe": "CWE-200", "owasp": "M9:2023",
                "evidence": "no .entitlements or embedded.provisioningprofile",
                "remediation": "Either Android-only OR stripped iOS bundle."}
    return {"name": "iOS entitlements present, no risky ones detected",
            "severity": "POSITIVE", "cwe": "CWE-732", "owasp": "M9:2023",
            "evidence": f"{len(s.get('entitlement_sources') or [])} sources scanned",
            "remediation": "Maintain. Re-audit on each App Store submission."}


def rule_risky_entitlements(s):
    risky = s.get("risky_entitlements") or []
    if not risky: return None
    debug_in_prod = any(r["key"] == "com.apple.security.get-task-allow" for r in risky)
    sev = "HIGH" if debug_in_prod else "MEDIUM"
    cvss = "7.5" if debug_in_prod else "5.3"
    return {"name": f"Risky iOS entitlements ({len(risky)})",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-732", "owasp": "M9:2023",
            "evidence": " | ".join(f"{r['key']}: {r['desc']}" for r in risky[:5]),
            "remediation": "Each entitlement weakens App Sandbox. (1) "
                           "get-task-allow=true in PROD = debugger can attach → "
                           "memory dump. (2) disable-library-validation = "
                           "unsigned dylib injection. (3) allow-jit = breaks "
                           "W^X mitigation. Review per Apple Code Signing Guide; "
                           "REMOVE entitlements not strictly required by App Store reviewer."}


IOS_SANDBOX_ENTITLEMENTS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_risky_entitlements,
]
