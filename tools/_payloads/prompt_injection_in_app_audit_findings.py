"""prompt_injection_in_app_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("prompt_injection_in_app_audit_total"):
        return None
    return {"name": "App-embedded LLM posture clean or absent",
            "severity": "POSITIVE",
            "evidence": (f"LLM API users={len(s.get('llm_api_users') or [])} "
                         f"SDK users={len(s.get('llm_sdk_users') or [])} "
                         f"sanitizers={s.get('sanitizer_uses', 0)}"),
            "remediation": "Continue passing user input through prompt-injection sanitization.",
            "cwe": "CWE-1039", "owasp": "M4:2023"}


def rule_no_sanitizer(s):
    callers = (s.get("llm_api_users") or []) + (s.get("llm_sdk_users") or [])
    if not callers or s.get("sanitizer_uses", 0) > 0:
        return None
    uc = s.get("user_concat_files") or []
    if not uc: return None
    return {"name": f"App embeds LLM client + concatenates user input in {len(uc)} site(s) without sanitization",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-1039", "owasp": "M4:2023",
            "evidence": f"LLM callers: {', '.join(callers[:4])} | concat sites: {', '.join(uc[:4])}",
            "remediation": "Wrap user input with delimiters (XML tags / system-prompt separation), strip override phrases ('ignore previous instructions'), keep user input out of system role. Consider llm-guard / Rebuff-style sanitizer."}


PROMPT_INJECTION_IN_APP_AUDIT_FINDING_RULES = [rule_positive_emit, rule_no_sanitizer]
