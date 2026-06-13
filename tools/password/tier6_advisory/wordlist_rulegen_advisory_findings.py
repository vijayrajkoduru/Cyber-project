"""wordlist_rulegen_advisory - findings rules (advisory-by-design).

A single INFO finding. §5 wordlist / rule generation (crunch, cewl, best64/
OneRule, Markov, PRINCE, mask, combinator, AI-curated lists) produces input
for offline/online cracking - it is a local generation step, not a remote
scan. The breach-exposure side (HIBP Pwned Passwords) IS probed live by
breach_exposure_audit. NEVER graded: always INFO.
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
            "(NOT a forge gap). Generate candidate wordlists + mutation rules "
            "locally (crunch / cewl / hashcat rules) to feed offline/online "
            "cracking. The breach-exposure side (HIBP Pwned Passwords) IS probed "
            "live by breach_exposure_audit. See module_playbooks/08_password.md §5."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-521",
        "owasp": "N/A",
    }


WORDLIST_RULEGEN_ADVISORY_FINDING_RULES = [rule_advisory]
