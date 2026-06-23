"""tflite_extraction_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("tflite_extraction_audit_total"):
        return None
    return {"name": "No TFLite / ONNX / PB models bundled",
            "severity": "POSITIVE", "evidence": "No model files in bundle",
            "remediation": "If you add ML later, prefer download-on-demand + cache encryption.",
            "cwe": "CWE-200", "owasp": "M10:2023"}


def rule_models_present(s):
    m = s.get("ml_models") or []
    if not m: return None
    # presence != vuln: a bundled model being extractable is an IP/asset note,
    # not a security defect by itself -> LOW.
    return {"name": f"{len(m)} ML model(s) bundled in plaintext ({s.get('total_kb', 0)} KB total)",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-200", "owasp": "M10:2023",
            "evidence": "Models: " + ", ".join(f"{e['name']}({e['ext']})" for e in m[:6]),
            "remediation": "If the model is proprietary, encrypt with key fetched from server post-attestation. Otherwise it is recoverable via `apktool d` (treat as a public asset)."}


TFLITE_EXTRACTION_AUDIT_FINDING_RULES = [rule_positive_emit, rule_models_present]
