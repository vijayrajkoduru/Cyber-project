"""bluetooth_active_advisory - findings rules (playbook §6 #57-66).

All INFO / advisory-by-design. Active BT/BLE attacks require RF proximity and
often specialized sniffer hardware (Ubertooth, nRF). Passive enumeration is
already handled by tier2_bluetooth scanners.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("Active Bluetooth/BLE attacks require physical RF proximity to the "
        "target device, frequently with specialized sniffer hardware "
        "(Ubertooth One, nRF52, btlejack), and active interaction with the "
        "device — not reachable from an external SaaS scanner.")

_TECHNIQUES = [
    ("§6 #57", "BLE pairing weak-key attack", "HIGH", _WHY,
     "Capture the BLE pairing exchange with btlejuice/gattacker on-site; require "
     "LE Secure Connections (not Legacy Pairing) and reject Just Works on "
     "sensitive characteristics.", "CWE-1240"),
    ("§6 #58", "BLE replay attack (btlejack)", "MEDIUM", _WHY,
     "Capture and replay BLE control PDUs with btlejack near the device; "
     "implement freshness/nonce + signed writes at the application layer.",
     "CWE-294"),
    ("§6 #59", "BLE sniff (Ubertooth / nRF)", "MEDIUM", _WHY,
     "Sniff the connection with Ubertooth/nRF; enforce LE encryption + Secure "
     "Connections so sniffed traffic is not plaintext.", "CWE-319"),
    ("§6 #61", "Bluetooth Classic PIN brute (redfang)", "HIGH", _WHY,
     "Brute the legacy PIN on-air with redfang; disable Legacy Pairing and "
     "require Secure Simple Pairing / Secure Connections with a strong key.",
     "CWE-521"),
    ("§6 #62", "BlueBorne (CVE-2017-0781 family)", "CRITICAL", _WHY,
     "Verify the device's BlueZ/stack version against the BlueBorne CVEs and "
     "patch; disable Bluetooth when not in use.", "CWE-787"),
    ("§6 #63", "Bluetooth Impersonation Attack (BIAS)", "HIGH", _WHY,
     "BIAS exploits legacy-auth role switches on-air; patch to a firmware that "
     "enforces mutual authentication + Secure Connections.", "CWE-290"),
    ("§6 #64", "Forward/Future-secrecy attack (KNOB-style)", "HIGH", _WHY,
     "KNOB downgrades the encryption key entropy during pairing; patch firmware "
     "and enforce a minimum 7-byte (ideally 16-byte) key length.", "CWE-326"),
    ("§6 #65", "BlueJacking / BlueSnarfing (bluesnarfer)", "MEDIUM", _WHY,
     "Test OBEX/profile exposure on-site; set the device non-discoverable, "
     "require authentication on OBEX, and patch legacy snarfing CVEs.",
     "CWE-200"),
    ("§6 #66", "Manual BLE protocol reverse-engineering", "INFO", _WHY,
     "Analyst-driven Wireshark + GATT RE on-site; out of scope for automated "
     "SaaS scanning.", "CWE-1395"),
]

BLUETOOTH_ACTIVE_ADVISORY_FINDING_RULES = build_advisory_rules(
    "bluetooth_active_advisory", _TECHNIQUES)
