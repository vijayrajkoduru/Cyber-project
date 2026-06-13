"""hash_identification_advisory - findings rules (advisory-by-design).

A single INFO finding. §4 hash identification operates on a hash the
customer ALREADY HAS - a local/input-driven analysis step (hashid /
name-that-hash / hash-identifier), not something an external scanner can
run against a remote target. NEVER graded: always INFO.
"""


def rule_advisory(s):
    if not s.get("advisory"):
        return None
    title = s.get("advisory_title") or ""
    return {
        "name": f"[ADVISORY-BY-DESIGN] {title}",
        "severity": "INFO",
        "evidence": s.get("advisory_reason") or "",
        "remediation": (
            "This technique cannot be SaaS-probed and is intentionally advisory "
            "(NOT a forge gap). Identify the hash locally with hashid / "
            "name-that-hash / hash-identifier. See module_playbooks/"
            "08_password.md §4."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-327",
        "owasp": "N/A",
    }


HASH_IDENTIFICATION_ADVISORY_FINDING_RULES = [rule_advisory]
