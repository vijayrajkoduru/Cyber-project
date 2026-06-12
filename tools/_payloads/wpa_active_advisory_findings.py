"""wpa_active_advisory - findings rules (playbook §2 #13,15,16,17,18,21,22,23,24,26).

All INFO / advisory-by-design. WEP/WPA active attacks require monitor-mode RF
capture and/or active frame injection (deauth) adjacent to the target. Safe
detection (handshake capturability + WPS/Pixie state) is already handled by
tier1_wifi scanners.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("WEP/WPA active attacks require monitor-mode 802.11 capture and/or "
        "active frame injection (deauth, EAPOL replay) adjacent to the target "
        "BSS — disruptive, RF-hardware-dependent, and not reachable from an "
        "external SaaS scanner.")

_TECHNIQUES = [
    ("§2 #13", "WEP IV collection + crack (aircrack-ng)", "CRITICAL", _WHY,
     "Collect IVs on-site and crack with aircrack-ng; WEP is fully broken — "
     "migrate any remaining WEP networks to WPA3-SAE immediately.", "CWE-326"),
    ("§2 #15", "Deauthentication attack (aireplay-ng -0)", "MEDIUM", _WHY,
     "Inject deauth frames on-site to force reauth; deploy 802.11w PMF so "
     "management frames are protected and deauth spoofing is blocked. NOTE: "
     "VulnusLab never runs deauth (disruptive active attack).", "CWE-770"),
    ("§2 #16", "PMKID capture (hcxdumptool, no client)", "HIGH", _WHY,
     "Capture the PMKID from the first EAPOL frame on-site; rotate to a 20+ char "
     "PSK outside any wordlist or move to WPA3-SAE (no offline-crackable PMKID).",
     "CWE-326"),
    ("§2 #17", "WPA handshake crack (hashcat mode 22000)", "HIGH", _WHY,
     "Crack a captured handshake offline; enforce long random PSKs / WPA3-SAE. "
     "(Capturability is detected live by wpa_handshake_capture_audit.)",
     "CWE-916"),
    ("§2 #18", "wifite automated workflow", "HIGH", _WHY,
     "wifite chains capture+crack on-site; harden PSK length + WPS state + PMF "
     "as above.", "CWE-326"),
    ("§2 #21", "KRACK attack (CVE-2017-13077)", "HIGH", _WHY,
     "KRACK exploits the 4-way-handshake key reinstallation on-air; patch all "
     "APs AND clients for the 2017 KRACK CVEs and require PMF.", "CWE-323"),
    ("§2 #22", "Karma attack (probe-response abuse)", "HIGH", _WHY,
     "Respond to client probes on-site to lure auto-join; harden client "
     "auto-join behavior (forget open networks, MDM).", "CWE-290"),
    ("§2 #23", "Wi-Fi covert channel", "MEDIUM", _WHY,
     "Detect anomalous 802.11 management/data patterns with a WIDS; "
     "analyst-driven.", "CWE-514"),
    ("§2 #24", "OneShot Pixie Dust attack", "HIGH", _WHY,
     "OneShot performs the offline Pixie Dust WPS attack on-site; disable WPS "
     "entirely. (WPS/Pixie state is detected live by wps_pin_audit.)", "CWE-326"),
    ("§2 #26", "Manual EAPOL replay attack", "MEDIUM", _WHY,
     "Analyst-driven EAPOL replay on-site; require PMF + current AP firmware.",
     "CWE-294"),
    ("§2 #25", "Manual handshake forensics", "INFO", _WHY,
     "Analyst-driven offline pcap analysis; out of scope for automated SaaS "
     "scanning.", "CWE-1395"),
]

WPA_ACTIVE_ADVISORY_FINDING_RULES = build_advisory_rules(
    "wpa_active_advisory", _TECHNIQUES)
