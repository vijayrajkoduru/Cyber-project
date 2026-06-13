"""offline_crack_advisory - findings rules (advisory-by-design).

A single INFO finding. §2 offline hash cracking (hashcat / john across NTLM,
NetNTLMv2, Kerberos, bcrypt, scrypt, Argon2, PBKDF2, JWT HS256, archive/vault
formats) requires the customer to supply the captured hash material and runs
on dedicated GPU hardware - there is no remote surface to scan. NEVER graded:
always INFO.
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
            "(NOT a forge gap). Run hashcat/john with SecLists + best64/OneRule "
            "rules on an isolated GPU rig against customer-supplied hashes. The "
            "live spray/brute surface those hashes come from is covered by "
            "auth_surface_audit + the tier3_ad roasting scanners. See "
            "module_playbooks/08_password.md §2."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-916",
        "owasp": "N/A",
    }


OFFLINE_CRACK_ADVISORY_FINDING_RULES = [rule_advisory]
