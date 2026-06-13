"""cloud_crack_advisory - findings rules (advisory-by-design).

A single INFO finding. §6 cloud/distributed cracking (Hashtopolis / NPK /
GPU rental) is operator-side infrastructure for accelerating offline
cracking on rented/owned GPUs - it targets the operator's own compute, not
the customer's environment, so there is no remote surface to scan. NEVER
graded: always INFO, advisory-by-design.
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
            "(NOT a forge gap). Use the playbook reference for manual / red-team "
            "execution on operator-owned GPU compute. See module_playbooks/"
            "08_password.md §6."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-916",
        "owasp": "N/A",
    }


CLOUD_CRACK_ADVISORY_FINDING_RULES = [rule_advisory]
