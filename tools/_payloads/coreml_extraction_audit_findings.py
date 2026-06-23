"""coreml_extraction_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("coreml_extraction_audit_total"):
        return None
    return {"name": "No CoreML models bundled",
            "severity": "POSITIVE", "evidence": "No .mlmodel / .mlpackage in bundle",
            "remediation": "If you add ML later, consider model encryption + on-device key gating.",
            "cwe": "CWE-200", "owasp": "M10:2023"}


def rule_models_present(s):
    m = s.get("coreml_models") or []
    if not m: return None
    # presence != vuln: an extractable bundled model is an IP/asset note, not a
    # security defect by itself -> LOW.
    return {"name": f"{len(m)} CoreML model(s) bundled in plaintext ({s.get('total_kb', 0)} KB total)",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-200", "owasp": "M10:2023",
            "evidence": "Models: " + ", ".join(e["name"] for e in m[:6]),
            "remediation": "If model represents IP / training-data investment, encrypt with on-device key (Keychain-stored) + decrypt at load. Otherwise classify as public asset."}


COREML_EXTRACTION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_models_present]
