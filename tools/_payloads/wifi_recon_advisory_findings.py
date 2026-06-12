"""wifi_recon_advisory - findings rules (playbook §1 #3-12).

All INFO / advisory-by-design. On-air Wi-Fi recon (hidden SSID, client probe
enum, channel hopping, signal mapping, war-driving, 6GHz/Wi-Fi 7 fingerprint)
requires monitor-mode RF adjacent to the target. Covered live only by an
on-LAN agent with the right adapter.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("On-air Wi-Fi enumeration requires a monitor-mode adapter capturing "
        "802.11 frames adjacent to the target access point — not reachable "
        "from an external SaaS scanner.")

_TECHNIQUES = [
    ("§1 #3", "Hidden SSID discovery", "LOW", _WHY,
     "Run airodump-ng on-site and observe probe/association frames to reveal "
     "hidden SSIDs; note that hiding the SSID is not a real control.", "CWE-200"),
    ("§1 #4", "Client probe-request enumeration", "MEDIUM", _WHY,
     "Capture client probe requests on-site to map device PNLs; configure "
     "managed clients to randomize MAC + avoid broadcasting known SSIDs.",
     "CWE-359"),
    ("§1 #5", "Channel-hopping scan", "INFO", _WHY,
     "airodump-ng channel hopping on-site enumerates all nearby BSS; "
     "informational reconnaissance.", "CWE-200"),
    ("§1 #6", "Signal-strength mapping (kismet)", "INFO", _WHY,
     "Map RSSI with kismet on-site to locate APs/clients; informational.",
     "CWE-200"),
    ("§1 #7", "Wigle GPS lookup / war-driving", "LOW", _WHY,
     "Correlate BSSID against wigle.net war-driving data; minimize the AP's "
     "geographic footprint exposure where feasible.", "CWE-200"),
    ("§1 #9", "Wi-Fi 6 / 6E / 7 capability fingerprint", "INFO", _WHY,
     "Parse beacon HE/EHT capability IEs on-site; informational fingerprint of "
     "the AP's generation + features.", "CWE-200"),
    ("§1 #10", "6 GHz band capability detect", "INFO", _WHY,
     "iw scan / on-air capture on-site to detect 6 GHz operation; "
     "informational.", "CWE-200"),
    ("§1 #11", "Manual creative client tracking", "INFO", _WHY,
     "Analyst-driven kismet tracking; out of scope for automated SaaS "
     "scanning.", "CWE-1395"),
    ("§1 #12", "Manual neighbor-AP map", "INFO", _WHY,
     "Analyst-driven RF survey; out of scope for automated SaaS scanning.",
     "CWE-1395"),
]

WIFI_RECON_ADVISORY_FINDING_RULES = build_advisory_rules(
    "wifi_recon_advisory", _TECHNIQUES)
