"""sidechannel_fault_advisory - findings rules.

ADVISORY-BY-DESIGN: a single INFO finding. These are lab hardware attacks
against silicon (not the firmware image) and several are destructive — out of
scope for SaaS VA. Never graded.
"""


def rule_advisory(s):
    if not s.get("sca_advisory"):
        return None
    techniques = s.get("sca_techniques") or []
    return {"name": "[ADVISORY-BY-DESIGN] Side-channel & fault-injection attacks",
            "severity": "INFO",
            "evidence": (f"{len(techniques)} §7 techniques require lab hardware (ChipWhisperer, "
                         f"oscilloscope, EM/laser rig) + physical silicon access; several are "
                         f"destructive — not performable by an external SaaS and out of scope for "
                         f"detection-only VA"),
            "remediation": ("Endpoint is advisory-by-design, NOT a forge gap. For a hardware "
                            "engagement: profile power/EM traces with a ChipWhisperer during crypto "
                            "operations (DPA/CPA for key recovery); attempt voltage/clock glitching "
                            "to skip secure-boot signature checks or unlock JTAG. Defensively: use "
                            "constant-time + masked crypto, glitch detectors, redundant signature "
                            "checks, and tamper-resistant packaging. See playbook §7."),
            "cwe": "CWE-1300", "owasp": "A02:2021"}


SIDECHANNEL_FAULT_ADVISORY_FINDING_RULES = [rule_advisory]
