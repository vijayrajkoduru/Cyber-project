"""rogue_ap_advisory - findings rules (playbook §5 #45-54).

All INFO / advisory-by-design. Rogue AP / Evil Twin are ACTIVE attacks
(broadcast a malicious AP) — PT not VA. VulnusLab never runs them; this tier
documents them as defensive advisories only.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("Rogue AP / Evil Twin techniques actively broadcast a malicious access "
        "point on the target RF — an active, potentially disruptive PT activity "
        "that VulnusLab (detection-only) does not perform.")

_TECHNIQUES = [
    ("§5 #45", "hostapd-wpe rogue AP", "HIGH", _WHY,
     "Detect rogue APs defensively with a WIDS (Kismet/wireless controller "
     "rogue-AP detection) and 802.11w PMF; never run the attack outside an "
     "authorized engagement.", "CWE-290"),
    ("§5 #46", "airbase-ng evil twin", "HIGH", _WHY,
     "Enable client-side server-cert validation + PMF; monitor for duplicate "
     "SSID/BSSID broadcasts with a WIDS.", "CWE-290"),
    ("§5 #47", "wifiphisher automated phishing", "HIGH", _WHY,
     "User-awareness training + 802.1X with cert validation defeats credential "
     "phishing captive portals; deploy rogue-AP containment.", "CWE-1021"),
    ("§5 #48", "Karma + captive-portal injection", "HIGH", _WHY,
     "Disable auto-join of open/known SSIDs on managed clients; deploy MDM "
     "profiles that forget open networks.", "CWE-290"),
    ("§5 #49", "DHCP + DNS spoofing on rogue AP", "HIGH", _WHY,
     "DHCP snooping + dynamic ARP inspection on the wired side; clients should "
     "use DoH/DoT to resist DNS spoofing on hostile networks.", "CWE-350"),
    ("§5 #50", "Forced-association deauth", "MEDIUM", _WHY,
     "Require PMF (802.11w) so management frames are protected and deauth "
     "spoofing is blocked; monitor deauth floods with a WIDS.", "CWE-770"),
    ("§5 #51", "Wi-Fi Pineapple workflow", "HIGH", _WHY,
     "Same defenses as evil twin: PMF, cert validation, WIDS rogue-AP "
     "containment, client auto-join hardening.", "CWE-290"),
    ("§5 #52", "EAP-Pickle (modern enterprise evil twin)", "HIGH", _WHY,
     "Enforce supplicant CA pinning + EAP-TLS so cloned enterprise SSIDs are "
     "rejected by clients.", "CWE-295"),
    ("§5 #53", "Manual victim-targeting strategy", "INFO", _WHY,
     "Analyst-driven, engagement-scoped; out of scope for automated SaaS "
     "scanning.", "CWE-1395"),
    ("§5 #54", "Manual captive-portal phishing design", "INFO", _WHY,
     "Analyst-driven content design; out of scope for automated SaaS scanning.",
     "CWE-1395"),
]

ROGUE_AP_ADVISORY_FINDING_RULES = build_advisory_rules("rogue_ap_advisory", _TECHNIQUES)
