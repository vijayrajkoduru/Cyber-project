"""data_safety_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("data_safety_audit_total"):
        return None
    return {"name": f"Data collection narrow ({s.get('data_type_count', 0)} types)",
            "severity": "POSITIVE",
            "evidence": "Collected: " + ", ".join(s.get("collected_data_types") or []) if s.get("collected_data_types") else "None detected",
            "remediation": "Continue declaring every collected data type in Google Play Data Safety section.",
            "cwe": "CWE-359", "owasp": "M9:2023"}


def rule_broad_collection(s):
    n = s.get("data_type_count", 0)
    if n < 4: return None
    sev = "HIGH" if n >= 6 else "MEDIUM"
    return {"name": f"App collects {n} sensitive data types - Data Safety declaration must match",
            "severity": sev, "cvss": "5.0",
            "cwe": "CWE-359", "owasp": "M9:2023",
            "evidence": "Collected: " + ", ".join(s.get("collected_data_types") or []),
            "remediation": "Map each collected data type to a row in Play Console > Data Safety. Misdeclaration triggers Play Store enforcement + GDPR/DPDP exposure."}


DATA_SAFETY_AUDIT_FINDING_RULES = [rule_positive_emit, rule_broad_collection]
