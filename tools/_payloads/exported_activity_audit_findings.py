"""exported_activity_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("exported_activity_audit_total"):
        return None
    return {"name": "No unprotected exported components",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} manifest(s) scanned",
            "remediation": "Continue gating exported components with android:permission of signature level.",
            "cwe": "CWE-927", "owasp": "M4:2023"}


def rule_sensitive_exposed(s):
    se = s.get("sensitive_exposed_components") or []
    if not se: return None
    return {"name": f"{len(se)} sensitive component(s) exported without permission",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-927", "owasp": "M4:2023",
            "evidence": "Components: " + ", ".join(f"{e['kind']}:{e['name']}" for e in se[:6]),
            "remediation": ("Set android:exported=\"false\" OR require android:permission with custom "
                            "signature-level permission. Any installed app can invoke unprotected exports "
                            "(login / payment / vault screens are particularly dangerous).")}


def rule_exposed_general(s):
    if s.get("sensitive_exposed_components"): return None
    e = s.get("exposed_components") or []
    if not e: return None
    return {"name": f"{len(e)} component(s) exported without permission gate",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-927", "owasp": "M4:2023",
            "evidence": "Components: " + ", ".join(f"{x['kind']}:{x['name']}" for x in e[:6]),
            "remediation": "Audit each. Default to exported=\"false\"; add permission only when truly needed."}


EXPORTED_ACTIVITY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_sensitive_exposed, rule_exposed_general]
