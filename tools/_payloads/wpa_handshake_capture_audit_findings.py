"""wpa_handshake_capture_audit - findings rules.

ZERO-FP: HIGH (offline-crackable) fires ONLY on a VALIDATED handshake
(handshake_captured, which the scanner sets only when tshark confirms at
least M1+M2 of the 4-way exchange). A raw EAPOL byte count is no longer
trusted on its own — a partial / unvalidated capture is INFO, never HIGH.
"""


def rule_airodump_missing(s):
    if not s.get("airodump_binary_missing"):
        return None
    return {"name": "airodump-ng binary not available",
            "severity": "INFO",
            "evidence": "shutil.which('airodump-ng') returned None and /usr/sbin/airodump-ng is absent",
            "remediation": ("Install aircrack-ng (`apt install aircrack-ng`) and run "
                            "the scanner from an agent host with a monitor-mode "
                            "capable Wi-Fi adapter."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_monitor_interface(s):
    if not s.get("no_monitor_interface"):
        return None
    return {"name": "No monitor-mode interface supplied",
            "severity": "INFO",
            "evidence": "options.interface was empty — handshake capture cannot proceed",
            "remediation": ("Run the monitor_mode_capability_audit probe first, "
                            "then pass options.interface=\"wlan0mon\" (or the "
                            "name from `iw dev`) plus options.channel."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_interface_missing(s):
    name = s.get("interface_not_present")
    if not name:
        return None
    return {"name": f"Wireless interface '{name}' not present on scanner host",
            "severity": "INFO",
            "evidence": f"/proc/net/dev did not list '{name}'",
            "remediation": ("Verify the adapter is plugged in and that "
                            "`airmon-ng start wlan0` produced the monitor "
                            "interface you pass via options.interface."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_permission_denied(s):
    if not s.get("airodump_permission_denied"):
        return None
    return {"name": "airodump-ng requires elevated privileges + monitor-mode iface",
            "severity": "INFO",
            "evidence": "exec failed with PermissionError",
            "remediation": ("Wireless capture needs CAP_NET_RAW + CAP_NET_ADMIN. "
                            "Re-run the scan backend with --privileged or grant "
                            "the capabilities via setcap. Or run the agent on a "
                            "workstation as root."),
            "cwe": "CWE-250", "owasp": "A04:2021"}


def rule_handshake_captured(s):
    # HIGH only on a tshark-VALIDATED handshake (M1+M2 present). The scanner
    # sets handshake_captured == handshake_validated.
    if not s.get("handshake_captured"):
        return None
    msgs = s.get("eapol_msg_numbers") or []
    full = set(msgs) >= {1, 2, 3, 4}
    return {"name": ("WPA/WPA2 4-way handshake CAPTURED (validated) — PSK is "
                     "offline-crackable"),
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-326", "owasp": "A02:2021",
            "evidence": ("airodump captured " + str(s.get("eapol_packets", 0)) +
                         " EAPOL frame(s) for target " + str(s.get("target_label", "")) +
                         "; tshark confirmed handshake message numbers " +
                         str(sorted(set(msgs))) +
                         (" (complete M1-M4)" if full else " (M1+M2 present — "
                          "ANonce+SNonce+MIC sufficient for offline crack)") +
                         " — usable for hashcat mode 22000 brute force"),
            "remediation": ("1) Rotate the WPA2-PSK to a 20+ char passphrase outside "
                            "any wordlist. 2) Migrate to WPA3-SAE which uses Dragonfly "
                            "and is not offline-crackable by handshake capture. "
                            "3) For enterprise: deploy WPA2/3-Enterprise with EAP-TLS "
                            "and certificate validation pinned. 4) Disable PMF=optional "
                            "and require Protected Management Frames (802.11w).")}


def rule_partial_handshake(s):
    # Some EAPOL frames seen but NOT a validated full sequence (retransmits,
    # incomplete exchange, or no tshark to resolve message numbers). This is
    # advisory context, NOT an offline-crackable handshake.
    if s.get("handshake_captured"):
        return None
    if not s.get("handshake_partial"):
        return None
    msgs = s.get("eapol_msg_numbers") or []
    return {"name": "Partial / unvalidated EAPOL frames captured (no crackable handshake)",
            "severity": "INFO",
            "cwe": "CWE-326", "owasp": "A02:2021",
            "evidence": ("airodump captured " + str(s.get("eapol_packets", 0)) +
                         " EAPOL frame(s) for target " + str(s.get("target_label", "")) +
                         " but a complete M1-M4 4-way handshake was NOT validated "
                         "(resolved message numbers: " + str(sorted(set(msgs)) or "none") +
                         "). These frames are insufficient for an offline PSK crack — "
                         "this is not a confirmed weakness."),
            "remediation": ("Re-run with a longer scan_duration during business hours "
                            "(more client (re)associations) to capture a full handshake "
                            "for assessment, or deauth-trigger only on networks you own. "
                            "Ensure tshark is installed on the scanner so handshake "
                            "message numbers can be validated.")}


def rule_no_handshake_present(s):
    if s.get("handshake_captured"):
        return None
    if s.get("handshake_partial"):
        return None  # covered by rule_partial_handshake
    if not s.get("eapol_packets") and s.get("aps_observed", 0) > 0:
        return None  # captured nothing but saw APs — neutral, not a positive
    if not s.get("aps_observed"):
        return None
    return {"name": "No EAPOL handshake observed during capture window",
            "severity": "POSITIVE",
            "evidence": ("airodump observed " + str(s.get("aps_observed", 0)) +
                         " AP(s) but captured " + str(s.get("eapol_packets", 0)) +
                         " EAPOL frame(s) — no full 4-way handshake within "
                         + str(s.get("scan_duration_sec", 0)) + "s"),
            "remediation": ("Continue running with PMF=required, WPA3-SAE preferred, "
                            "and minimum 20-char PSKs. Re-test periodically with "
                            "longer scan_duration during business hours when "
                            "clients are reauthenticating.")}


WPA_HANDSHAKE_CAPTURE_AUDIT_FINDING_RULES = [
    rule_airodump_missing,
    rule_no_monitor_interface,
    rule_interface_missing,
    rule_permission_denied,
    rule_handshake_captured,
    rule_partial_handshake,
    rule_no_handshake_present,
]
