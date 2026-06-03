"""autofill_form_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("autofill_form_audit_total"):
        return None
    return {"name": "Autofill / form-cache controls clean",
            "severity": "POSITIVE",
            "evidence": (f"Android sensitive={len(s.get('android_sensitive') or [])} "
                         f"protected={s.get('android_autofill_off', 0)} | "
                         f"iOS textContentType misuse={len(s.get('ios_textcontent_misuse') or [])}"),
            "remediation": ("Continue using importantForAutofill=\"no\" on sensitive Android EditTexts "
                            "and textContentType=.password / .oneTimeCode on iOS sensitive fields."),
            "cwe": "CWE-524", "owasp": "M9:2023"}


def rule_android_autofill_open(s):
    n = s.get("android_unprotected") or 0
    if not n:
        return None
    return {"name": f"Android: {n} sensitive field(s) participate in autofill framework",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-524", "owasp": "M9:2023",
            "evidence": ("Sensitive EditTexts present without importantForAutofill=\"no\". "
                         f"Total sensitive={len(s.get('android_sensitive') or [])}, "
                         f"protected={s.get('android_autofill_off', 0)}"),
            "remediation": ("Add android:importantForAutofill=\"noExcludeDescendants\" on parent layouts "
                            "or per-field on every credential / payment EditText.")}


def rule_ios_textcontent_misuse(s):
    misuse = s.get("ios_textcontent_misuse") or []
    if not misuse:
        return None
    kinds = sorted({m.get("type") for m in misuse})
    return {"name": f"iOS: {len(misuse)} field(s) declare non-secret textContentType on sensitive screen",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-524", "owasp": "M9:2023",
            "evidence": f"Misused textContentType values: {', '.join(list(kinds)[:6])}",
            "remediation": ("Use textContentType=.password / .newPassword / .oneTimeCode on credential fields. "
                            "Generic types (.name, .addressCity) let iOS QuickType cache the entry.")}


AUTOFILL_FORM_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_android_autofill_open,
    rule_ios_textcontent_misuse,
]
