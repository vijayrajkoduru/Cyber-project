"""tapjacking_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("tapjacking_audit_total", 0)
    if n > 0:
        return {"name": f"Tapjacking protection present ({n} occurrence(s))",
                "severity": "POSITIVE",
                "cwe": "CWE-1021", "owasp": "M3:2023",
                "evidence": f"filterTouchesWhenObscured found in {len(s.get('tapjacking_protection_hits') or [])} files",
                "remediation": "Maintain. Ensure ALL sensitive Views (payment, "
                               "settings, confirm-action buttons) have the attribute."}
    return None


def rule_no_tapjacking_protection(s):
    n = s.get("tapjacking_audit_total", 0)
    if n > 0: return None
    return {"name": "No tapjacking protection detected",
            "severity": "LOW",
            "cwe": "CWE-1021", "owasp": "M3:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, no filterTouchesWhenObscured",
            "remediation": "For sensitive Views (Confirm Purchase, Send Money, "
                           "Enable Permission), add android:filterTouchesWhenObscured='true' "
                           "in layout XML. View.setFilterTouchesWhenObscured(true) for "
                           "programmatic views. Mitigates overlay attacks from "
                           "draw-over-other-apps permission misuse."}
