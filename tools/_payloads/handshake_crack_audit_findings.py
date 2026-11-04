"""handshake_crack_audit - findings rules.

Offline recovery of a WPA/WPA2 pre-shared key from a captured 4-way
handshake or PMKID. The capture is produced on-site by the VulnusLab
Wi-Fi capture agent (monitor-mode adapter near the AP) and uploaded here;
this host only does the compute-only offline crack, never live RF.
"""


def rule_cracker_missing(s):
    if not s.get("cracker_missing"):
        return None
    return {"name": "No WPA cracker available on analysis host",
            "severity": "INFO",
            "evidence": "neither aircrack-ng nor hashcat found on PATH",
            "remediation": ("Install aircrack-ng (`apt install aircrack-ng`) or "
                            "hashcat on the analysis host so uploaded captures "
                            "can be tested against a wordlist."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_no_capture(s):
    if not s.get("no_capture"):
        return None
    return {"name": "No capture file supplied for offline crack",
            "severity": "INFO",
            "evidence": str(s.get("no_capture"))[:200],
            "remediation": ("Upload a handshake (.cap/.pcap/.pcapng) or PMKID "
                            "(.22000/.hccapx) capture via "
                            "/api/wireless/handshake_crack/upload, then pass its "
                            "returned capture_path in options."),
            "cwe": "CWE-20", "owasp": "A04:2021"}


def rule_no_handshake_in_capture(s):
    if not s.get("no_handshake"):
        return None
    return {"name": "Capture contains no usable WPA handshake / PMKID",
            "severity": "INFO",
            "evidence": str(s.get("no_handshake"))[:200],
            "remediation": ("Re-capture: ensure a client (re)authenticates while "
                            "recording, or capture the PMKID directly. The agent's "
                            "--deauth option forces a reconnect to produce a handshake."),
            "cwe": "CWE-20", "owasp": "A04:2021"}


def rule_key_recovered(s):
    key = s.get("recovered_key")
    if not key:
        return None
    ssid = s.get("ssid") or "the target network"
    return {"name": f"WPA/WPA2 passphrase recovered for {ssid}",
            "severity": "CRITICAL",
            "evidence": (f"Offline crack recovered the pre-shared key from the "
                         f"captured handshake using wordlist "
                         f"'{s.get('wordlist_name') or 'supplied list'}'. "
                         f"Passphrase length {len(str(key))}."),
            "remediation": ("The Wi-Fi passphrase is weak - it appears in a common "
                            "wordlist and can be recovered offline from a single "
                            "captured handshake. Set a long (>=16 char) random "
                            "passphrase, prefer WPA3-SAE, and disable WPS. Rotate "
                            "the PSK and treat it as compromised."),
            "cwe": "CWE-521", "owasp": "A07:2021"}


def rule_key_not_recovered(s):
    if not s.get("crack_ran") or s.get("recovered_key"):
        return None
    return {"name": "WPA/WPA2 passphrase NOT recovered within wordlist",
            "severity": "INFO",
            "evidence": (f"Tested {s.get('candidates_tested') or 'the supplied'} "
                         f"candidates from '{s.get('wordlist_name') or 'wordlist'}' "
                         f"without recovering the key."),
            "remediation": ("Not proof the passphrase is strong - only that it is "
                            "absent from this wordlist. Try a larger wordlist or "
                            "targeted rules. Absence of a crack is NOT a pass."),
            "cwe": "CWE-521", "owasp": "A07:2021"}


HANDSHAKE_CRACK_AUDIT_FINDING_RULES = [
    rule_cracker_missing,
    rule_no_capture,
    rule_no_handshake_in_capture,
    rule_key_recovered,
    rule_key_not_recovered,
]
