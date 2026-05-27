"""nsec_walking — findings rules."""
def rule_nsec(s):
    if not s.get("nsec_seen"): return None
    return {"name":"NSEC zone enumeration possible (zone is walkable)","severity":"MEDIUM","cvss":"5.3",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"NSEC chain reveals next name: {s.get('nsec_next_name','?')}",
            "remediation":"Switch from NSEC to NSEC3 (RFC 5155) to prevent zone walking. NSEC reveals the entire zone structure."}

def rule_nsec3_opt_out(s):
    if not s.get("nsec3_seen"): return None
    if not s.get("nsec3_opt_out"): return None
    return {"name":"NSEC3 with opt-out flag (partial zone enumerable)","severity":"LOW","cvss":"3.7",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":"NSEC3 opt-out flag set — unsigned delegations not covered",
            "remediation":"Disable opt-out unless required (improves zone walking resistance)."}

def rule_nsec3_low_iter(s):
    if not s.get("nsec3_seen"): return None
    it = s.get("nsec3_iterations", 0)
    if it == 0 or it >= 100: return None
    return {"name":f"NSEC3 iteration count low ({it})","severity":"LOW","cvss":"3.1",
            "cwe":"CWE-916","owasp":"M5:2023",
            "evidence":f"Iterations: {it}",
            "remediation":"Use NSEC3 iterations >= 100 (RFC 5155 §10.3). Low iteration count makes offline dictionary attacks faster."}

def rule_secure(s):
    if s.get("nsec_seen") or not s.get("nsec3_seen"): return None
    if s.get("nsec3_opt_out"): return None
    it = s.get("nsec3_iterations", 0)
    if it > 0 and it < 100: return None
    return {"name":"NSEC3 properly configured (no opt-out, secure iterations)","severity":"POSITIVE",
            "evidence":f"NSEC3 with {it} iterations, no opt-out",
            "remediation":"Maintain — zone walking is well-mitigated.",
            "cwe":"CWE-200","owasp":"M5:2023"}

NSEC_WALKING_FINDING_RULES = [rule_nsec, rule_nsec3_opt_out, rule_nsec3_low_iter, rule_secure,
    rule_positive_emit,
]

def rule_positive_emit(s):
    """POSITIVE-emit when no risk indicators present (VL-FORGE pattern)."""
    if s.get("nsec_walkable") or s.get("nsec_records"):
        return None
    return {
        "name": "No NSEC/NSEC3 zone enumeration possible",
        "severity": "POSITIVE",
        "evidence": "Domain either not signed with NSEC or NSEC3 hashed correctly",
        "remediation": "Maintain - NSEC3 (vs plain NSEC) prevents zone enumeration.",
        "cwe": "CWE-200", "owasp": "N/A"
    }
