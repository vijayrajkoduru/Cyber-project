"""tracker_sdk_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("tracker_sdk_audit_total", 0)
    if n > 0: return None
    return {"name": "No third-party tracker SDKs detected",
            "severity": "POSITIVE",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files",
            "remediation": "Excellent privacy posture. Maintain."}


def rule_session_replay(s):
    by_cat = s.get("trackers_by_category") or {}
    sr = by_cat.get("session_replay") or []
    if not sr: return None
    return {"name": f"SESSION REPLAY SDK detected: {', '.join(sr)}",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": ", ".join(sr),
            "remediation": "Session replay records EVERY user interaction including "
                           "text input. If you handle PII / health / finance, this is "
                           "a GDPR / HIPAA / PCI-DSS risk. Verify: (1) explicit user "
                           "opt-in, (2) field-masking for sensitive inputs, (3) data "
                           "stays in your region, (4) Privacy policy DISCLOSURE."}


def rule_high_tracker_count(s):
    n = s.get("tracker_sdk_audit_total", 0)
    if n < 5: return None
    sev = "MEDIUM" if n < 10 else "HIGH"
    cvss = "5.3" if n < 10 else "7.0"
    by = s.get("trackers_by_category") or {}
    summary = " | ".join(f"{k}: {len(v)}" for k, v in by.items())
    return {"name": f"{n} tracker SDKs detected — high privacy attack surface",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": summary,
            "remediation": "Each tracker SDK has its own dependency tree + own "
                           "privacy policy + own incidents (e.g. AppsFlyer 2023 "
                           "data sharing controversy). Audit each via the App Defense "
                           "Alliance database. Disclose ALL in Play Store Data Safety "
                           "/ App Store Privacy Nutrition. Most tracker SDKs collect "
                           "device IDs that Google now classifies as personal data."}


def rule_tracker_inventory(s):
    n = s.get("tracker_sdk_audit_total", 0)
    if n == 0: return None
    found = s.get("trackers_found") or []
    return {"name": f"Tracker SDK inventory ({n} detected)",
            "severity": "INFO" if n < 5 else "LOW",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": " | ".join(f"{t['name']}/{t['category']}" for t in found[:15]),
            "remediation": "Map each to your Privacy Policy + Data Safety disclosure. "
                           "Apple App Privacy Nutrition Label and Google Play Data "
                           "Safety form REQUIRE accurate listing per category."}
