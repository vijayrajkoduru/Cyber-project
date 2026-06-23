"""permission_overask_audit - findings rules."""


def rule_positive_emit(s):
    # Only positive when no candidate over-ask was found at all.
    if s.get("overasked_permissions"):
        return None
    return {"name": "Declared permissions all used in code",
            "severity": "POSITIVE",
            "evidence": f"Declared={len(s.get('declared_permissions') or [])}",
            "remediation": "Continue declaring only what you use; remove unused entries on every release.",
            "cwe": "CWE-250", "owasp": "M9:2023"}


def rule_overask(s):
    oa = s.get("overasked_permissions") or []
    if not oa: return None
    # presence != over-ask: a heuristic partial code scan can't prove a
    # permission is unused (usage may live past the per-file/byte caps, in
    # reflection, or in a library). Report as INFO for manual confirmation,
    # never a graded MEDIUM.
    return {"name": f"{len(oa)} permission(s) declared with no usage found in partial code scan",
            "severity": "INFO",
            "cwe": "CWE-250", "owasp": "M9:2023",
            "evidence": ("Permissions: " + ", ".join(oa[:8])
                         + " | NOTE: heuristic scan (per-file/byte capped); absence of a usage marker is "
                         "not proof the permission is unused."),
            "remediation": ("Manually confirm whether each is genuinely unused (check reflection, libraries, "
                            "and full source). Remove truly-unused <uses-permission> entries; Play Store + "
                            "Apple App Review penalize unjustified permission requests.")}


PERMISSION_OVERASK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_overask]
