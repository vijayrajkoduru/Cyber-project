"""ondevice_llm_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("ondevice_llm_audit_total"):
        return None
    return {"name": "No on-device LLM detected",
            "severity": "POSITIVE", "evidence": "No llama.cpp/mlc-llm references or >100MB models",
            "remediation": "If you ship on-device LLM later, encrypt model + version-pin runtime.",
            "cwe": "CWE-200", "owasp": "M10:2023"}


def rule_large_model_bundled(s):
    lm = s.get("large_models") or []
    if not lm: return None
    return {"name": f"{len(lm)} large LLM model(s) bundled in-app",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-200", "owasp": "M10:2023",
            "evidence": "Models: " + ", ".join(f"{e['name']}({e['mb']}MB)" for e in lm[:4]),
            "remediation": "Consider download-on-demand to reduce app size + revoke model on misuse. Models are recoverable via apktool."}


def rule_llm_sdk(s):
    sdk = s.get("llm_sdk_users") or []
    if not sdk: return None
    return {"name": f"On-device LLM SDK present in {len(sdk)} class(es)",
            "severity": "INFO", "cvss": "0.0",
            "cwe": "CWE-200", "owasp": "M10:2023",
            "evidence": "SDK refs: " + ", ".join(sdk[:6]),
            "remediation": "Apply prompt-injection defenses + model integrity check on every load. Pair with prompt_injection_in_app_audit findings."}


ONDEVICE_LLM_AUDIT_FINDING_RULES = [rule_positive_emit, rule_large_model_bundled, rule_llm_sdk]
