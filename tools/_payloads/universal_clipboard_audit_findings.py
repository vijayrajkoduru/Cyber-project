"""universal_clipboard_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("universal_clipboard_audit_total"):
        return None
    return {"name": "iOS clipboard usage scoped or absent",
            "severity": "POSITIVE",
            "evidence": (f"UIPasteboard.general users={len(s.get('pasteboard_users') or [])} "
                         f"local-only={s.get('local_only_usage', 0)} "
                         f"expiration={s.get('expiration_usage', 0)}"),
            "remediation": "Continue scoping pasteboard with UIPasteboardOptionLocalOnly + expiration.",
            "cwe": "CWE-668", "owasp": "M9:2023"}


def rule_sensitive_universal(s):
    co = s.get("sensitive_co_located") or []
    if not co:
        return None
    return {"name": f"Sensitive symbols co-located with UIPasteboard.general in {len(co)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-668", "owasp": "M9:2023",
            "evidence": "Files: " + ", ".join(co[:6]),
            "remediation": ("Replace UIPasteboard.general with a named pasteboard + "
                            "UIPasteboardOption.localOnly: true + expirationDate: Date(+60s). "
                            "Default general pasteboard syncs to Mac / iPad via Universal Clipboard.")}


def rule_no_local_only(s):
    if s.get("sensitive_co_located"):
        return None
    if not s.get("pasteboard_users") or s.get("local_only_usage", 0) > 0:
        return None
    return {"name": f"UIPasteboard.general used in {len(s.get('pasteboard_users') or [])} class(es) without localOnly",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-668", "owasp": "M9:2023",
            "evidence": "Pasteboard users: " + ", ".join((s.get('pasteboard_users') or [])[:6]),
            "remediation": "Pass UIPasteboardOption.localOnly: true on setItems to disable Universal Clipboard sync."}


UNIVERSAL_CLIPBOARD_AUDIT_FINDING_RULES = [rule_positive_emit, rule_sensitive_universal, rule_no_local_only]
