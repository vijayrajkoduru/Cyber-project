"""implicit_intent_extras_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("implicit_intent_extras_audit_total"):
        return None
    return {"name": "Implicit intents carry no sensitive extras",
            "severity": "POSITIVE",
            "evidence": f"Explicit-intent uses={s.get('explicit_intent_uses', 0)}; no sensitive putExtra near implicit ACTION_SEND/VIEW",
            "remediation": "Continue using explicit intents (setComponent / setPackage) for any auth/payment data.",
            "cwe": "CWE-927", "owasp": "M4:2023"}


def rule_leaky_implicit(s):
    le = s.get("leaky_implicit_intents") or []
    if not le: return None
    sample = ", ".join(f"{e['file']} ({','.join(e['extras'][:3])})" for e in le[:4])
    return {"name": f"Implicit intent with sensitive extras in {len(le)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-927", "owasp": "M4:2023",
            "evidence": f"Hits: {sample}",
            "remediation": ("Add setComponent(new ComponentName(...)) or setPackage() before startActivity. "
                            "ACTION_SEND/VIEW with sensitive extras broadcasts to every matching app on the device.")}


IMPLICIT_INTENT_EXTRAS_AUDIT_FINDING_RULES = [rule_positive_emit, rule_leaky_implicit]
