"""tracking_sdk_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("tracking_sdk_audit_total"):
        return None
    n = s.get("tracker_count", 0)
    return {"name": f"Tracker SDK count low ({n})",
            "severity": "POSITIVE",
            "evidence": "Detected: " + ", ".join(s.get("detected_trackers") or []) if s.get("detected_trackers") else "None",
            "remediation": "Continue declaring every embedded tracker in Privacy Manifest / Data Safety.",
            "cwe": "CWE-359", "owasp": "M9:2023"}


def rule_many_trackers(s):
    n = s.get("tracker_count", 0)
    if n < 3: return None
    sev = "HIGH" if n >= 8 else "MEDIUM"
    return {"name": f"{n} third-party tracker/analytics SDK(s) bundled",
            "severity": sev, "cvss": "5.0" if sev == "MEDIUM" else "7.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "Detected: " + ", ".join(s.get("detected_trackers") or [])[:200],
            "remediation": "Audit each: confirm declared in Apple Privacy Manifest / Google Data Safety, document legal basis (consent / legitimate interest), drop SDKs that aren't actively used."}


TRACKING_SDK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_many_trackers]
