"""Shared builder for wireless advisory-by-design findings rules.

The wireless module's RF / hardware / LAN-adjacent technique families (WPA3,
Enterprise EAP, Rogue AP, Bluetooth active, NFC/RFID, Cellular/SDR) cannot be
actively probed from an external SaaS scanner. To surface every playbook
technique in the customer report WITHOUT fabricating graded findings, each
advisory scanner emits one INFO finding per technique via this builder.

HARD RULE enforced here: the emitted severity is ALWAYS "INFO" and
vulnerable-ness is false. The planned playbook severity for the technique (if
the customer ran it on a host with the right hardware) is recorded in the
remediation/context text ONLY — it is never used as the finding severity. This
guarantees zero false positives from the advisory tier.

Each technique tuple: (playbook_ref, title, planned_sev, why_advisory, how_to_test, cwe)
"""


def make_advisory_rule(gate_key: str, ref: str, title: str, planned_sev: str,
                       why_advisory: str, how_to_test: str, cwe: str = "CWE-1395"):
    """Build a single finding rule that emits an INFO [ADVISORY-BY-DESIGN]
    finding when state[gate_key] is truthy."""
    def _rule(s):
        if not s.get(gate_key):
            return None
        return {
            "name": f"[ADVISORY-BY-DESIGN] {ref} {title}",
            "severity": "INFO",          # ALWAYS INFO — never the planned severity
            "cvss": "0.0",
            "cwe": cwe,
            "owasp": "N/A",
            "evidence": (
                "Advisory-by-design: this technique cannot be probed from an "
                "external SaaS scanner. " + why_advisory + " No live scan was "
                "performed against the target and NO vulnerability is asserted."
            ),
            "remediation": (
                f"Planned severity if confirmed on-site: {planned_sev} (informational "
                f"only — NOT a finding severity). How to test for real: {how_to_test} "
                "See module_playbooks/18_wireless.md for the full procedure."
            ),
        }
    _rule.__name__ = "rule_" + gate_key + "_" + ref.replace("#", "n").replace(" ", "")
    return _rule


def build_advisory_rules(gate_key: str, techniques: list) -> list:
    """Build a list of advisory rules from a technique table.
    techniques: list of (ref, title, planned_sev, why_advisory, how_to_test[, cwe])."""
    rules = []
    for t in techniques:
        ref, title, planned_sev, why_advisory, how_to_test = t[0], t[1], t[2], t[3], t[4]
        cwe = t[5] if len(t) > 5 else "CWE-1395"
        rules.append(make_advisory_rule(gate_key, ref, title, planned_sev,
                                        why_advisory, how_to_test, cwe))
    return rules
