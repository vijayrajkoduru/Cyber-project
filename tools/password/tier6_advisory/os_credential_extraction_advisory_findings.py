"""os_credential_extraction_advisory - findings rules (advisory-by-design).

A single INFO finding. §7 OS-credential extraction (SAM/SYSTEM hive dump,
LSASS/Mimikatz, NTDS.dit, DPAPI, /etc/shadow, macOS Keychain, browser-saved
passwords) is POST-COMPROMISE: every technique requires an existing
administrative/root foothold ON the host. An external SaaS scanner has no
such foothold. NEVER graded: always INFO (post-compromise primitive, not a
live finding - per advisory-never-graded-severity feedback).
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
            "(NOT a forge gap). Every §7 technique is post-compromise (MITRE "
            "ATT&CK Credential Access TA0006) and requires an existing "
            "administrative/root foothold - it belongs to a manual / red-team / "
            "post-exploitation engagement under explicit authorization. See "
            "module_playbooks/08_password.md §7."
        ),
        "cwe": s.get("advisory_cwe") or "CWE-522",
        "owasp": "N/A",
    }


OS_CREDENTIAL_EXTRACTION_ADVISORY_FINDING_RULES = [rule_advisory]
