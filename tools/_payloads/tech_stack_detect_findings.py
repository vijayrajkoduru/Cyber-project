"""tech_stack_detect findings."""

def rule_f(s):
    techs = s.get("techs") or []
    if not techs: return None
    return {"name":f"Tech stack identified: {', '.join(techs)}","severity":"INFO",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"{len(techs)} technologies",
            "remediation":"Fingerprinting is unavoidable for web tech. Keep all detected stacks patched + minimize version disclosure."}
def rule_n(s):
    if (s.get("techs") or []): return None
    return {"name":"No common tech-stack signatures matched","severity":"POSITIVE",
            "evidence":"No CMS/framework markers in body or headers","remediation":"Custom-built or well-hardened site.",
            "cwe":"CWE-200","owasp":"M2:2023"}
TECH_STACK_DETECT_FINDING_RULES = [rule_f, rule_n]
