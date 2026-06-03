"""screen_overlay_protection_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("screen_overlay_protection_audit_total"):
        return None
    return {"name": "Overlay-tap protection present or no sensitive views",
            "severity": "POSITIVE",
            "evidence": (f"filterTouches={len(s.get('filter_touches_users') or [])} "
                         f"OBSCURED handlers={len(s.get('obscured_flag_handlers') or [])} "
                         f"sensitive views={len(s.get('sensitive_views') or [])}"),
            "remediation": "Continue using setFilterTouchesWhenObscured(true) on payment / login surfaces.",
            "cwe": "CWE-1021", "owasp": "M4:2023"}


def rule_unprotected_sensitive(s):
    u = s.get("unprotected_sensitive_views") or []
    if not u:
        return None
    return {"name": f"{len(u)} sensitive view(s) missing overlay-tap protection",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-1021", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(u[:6]),
            "remediation": ("Add android:filterTouchesWhenObscured=\"true\" on the root view of every "
                            "login / PIN / payment Activity; reject touches when FLAG_WINDOW_IS_OBSCURED "
                            "is set (tapjacking via overlay).")}


SCREEN_OVERLAY_PROTECTION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_unprotected_sensitive]
