"""hardware_interface_advisory - findings rules.

ADVISORY-BY-DESIGN: every finding here is INFO. UART/JTAG/SWD work requires
physical possession + bench hardware and cannot be SaaS-probed. Serial-console
hints extracted from an uploaded blob are surfaced as INFO context only — never
graded.
"""


def rule_advisory(s):
    if not s.get("hw_iface_advisory"):
        return None
    techniques = s.get("hw_iface_techniques") or []
    return {"name": "[ADVISORY-BY-DESIGN] UART / JTAG / SWD hardware debug interfaces",
            "severity": "INFO",
            "evidence": (f"{len(techniques)} §6 techniques require physical device access + bench "
                         f"hardware (logic analyser, JTAGulator, OpenOCD adapter, BusPirate) — not "
                         f"reachable from an external SaaS scanner"),
            "remediation": ("Endpoint is advisory-by-design, NOT a forge gap. Perform on-bench: "
                            "(1) locate UART TX/RX/GND with a logic analyser and auto-detect baud; "
                            "(2) discover JTAG/SWD pads with a JTAGulator or Glasgow; (3) attach via "
                            "OpenOCD and dump/inspect flash; (4) check whether the serial console "
                            "drops to an unauthenticated root shell. Defensively: disable production "
                            "UART consoles, blow JTAG/debug-disable fuses, require console auth, and "
                            "remove debug pads or fill vias. See playbook §6."),
            "cwe": "CWE-1191", "owasp": "A05:2021"}


def rule_console_context(s):
    cons = s.get("hw_console_lines") or []
    if not cons and not s.get("hw_serial_getty"):
        return None
    ev = []
    if cons:
        ev.append("console: " + ", ".join(cons[:4]))
    if s.get("hw_serial_getty"):
        ev.append("serial getty/login present")
    if s.get("hw_jtag_swd_strings"):
        ev.append("JTAG/SWD strings present")
    return {"name": "[ADVISORY-BY-DESIGN] Serial console / debug configuration hints in firmware",
            "severity": "INFO",
            "evidence": "; ".join(ev),
            "remediation": ("The firmware references a serial console (and possibly a getty/login on "
                            "it). On the physical device, probe that UART — if it presents a shell "
                            "without authentication, it is an unauthenticated local-root path. This "
                            "is context for on-bench testing, not a remote vulnerability. Disable or "
                            "password-gate the production console. See playbook §6 #50/#57."),
            "cwe": "CWE-1191", "owasp": "A05:2021"}


HARDWARE_INTERFACE_ADVISORY_FINDING_RULES = [rule_advisory, rule_console_context]
