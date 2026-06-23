"""tracking_sdk_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("tracking_sdk_audit_total"):
        return None
    n = s.get("tracker_count", 0)
    # If >=3 trackers are bundled (even if dormant), the INFO rule covers it;
    # don't also emit a "count low" POSITIVE.
    if n >= 3:
        return None
    return {"name": f"Tracker SDK count low ({n})",
            "severity": "POSITIVE",
            "evidence": "Detected: " + ", ".join(s.get("detected_trackers") or []) if s.get("detected_trackers") else "None",
            "remediation": "Continue declaring every embedded tracker in Privacy Manifest / Data Safety.",
            "cwe": "CWE-359", "owasp": "M9:2023"}


def rule_many_trackers(s):
    n = s.get("tracker_count", 0)
    if n < 3: return None
    active = s.get("active_tracker_count", 0)
    detected = ", ".join(s.get("detected_trackers") or [])[:200]
    # presence != active tracking: if no SDK shows an init/usage call site, the
    # bundled packages may be dormant transitive deps -> INFO, not graded.
    if active < 1:
        return {"name": f"{n} tracker/analytics SDK(s) bundled but no active initialization observed",
                "severity": "INFO",
                "cwe": "CWE-359", "owasp": "M9:2023",
                "evidence": f"Detected (classpath only): {detected}. No initialize()/logEvent()/getInstance() call site found.",
                "remediation": ("Confirm whether these are actually used. Remove unused transitive trackers; "
                                "for any that are active, declare them in the Apple Privacy Manifest / Google Data Safety.")}
    sev = "HIGH" if (n >= 8 and active >= 3) else "MEDIUM"
    return {"name": f"{n} third-party tracker/analytics SDK(s) bundled ({active} actively initialized)",
            "severity": sev, "cvss": "5.0" if sev == "MEDIUM" else "7.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": f"Detected: {detected} | Active: " + ", ".join(s.get("active_trackers") or [])[:120],
            "remediation": "Audit each: confirm declared in Apple Privacy Manifest / Google Data Safety, document legal basis (consent / legitimate interest), drop SDKs that aren't actively used."}


TRACKING_SDK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_many_trackers]
