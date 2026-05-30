"""prompt_injection_static_check — findings rules."""


def rule_positive_emit(s):
    llm = s.get("llm_call_files") or []
    flow = s.get("input_in_llm_file") or []
    if not llm:
        return {"name": "No LLM API calls detected in bundle",
                "severity": "POSITIVE",
                "cwe": "CWE-1395", "owasp": "M9:2023",
                "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 LLM markers",
                "remediation": "App doesn't talk to a hosted LLM — no prompt-injection "
                               "surface from this static check. (May still ship on-device "
                               "LLM — see ai_ml_model_detection.)"}
    if llm and not flow:
        return {"name": f"LLM API used ({len(llm)} file(s)), no user-input flow detected",
                "severity": "POSITIVE",
                "cwe": "CWE-1395", "owasp": "M9:2023",
                "evidence": f"llm files: {len(llm)} | input+llm: 0",
                "remediation": "Static analysis didn't find user-input → LLM-call paths. "
                               "Could be server-side input (safer) OR intermediate "
                               "variables hiding the data flow. Manually verify."}
    return None


def rule_prompt_injection_risk(s):
    flow = s.get("input_in_llm_file") or []
    if not flow: return None
    return {"name": f"PROMPT-INJECTION RISK — {len(flow)} file(s) mix user input + LLM call",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1336", "owasp": "M3:2023",
            "evidence": " | ".join(flow[:5]),
            "remediation": "Each flagged file contains BOTH user-input source AND LLM "
                           "API call markers. (1) Use separator tokens (XML-style "
                           "delimiters) around user input in prompts. (2) Treat LLM "
                           "output as UNTRUSTED — don't render rich HTML / execute "
                           "code suggestions / call tools without confirmation. "
                           "(3) Use system message to constrain behavior. "
                           "(4) Read OWASP LLM Top 10 #1 (Prompt Injection) + "
                           "Anthropic's API safety guidance. (5) Add a content filter "
                           "to detect jailbreak patterns before sending to LLM."}
