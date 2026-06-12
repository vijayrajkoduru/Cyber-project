"""nfc_rfid_advisory - findings rules (playbook §7 #67-74).

All INFO / advisory-by-design. NFC/RFID attacks are physical-layer, require
centimeter proximity + Proxmark3 / Flipper Zero hardware.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("NFC/RFID techniques operate at the physical layer, require "
        "centimeter-range proximity to the credential/tag, and need "
        "specialized hardware (Proxmark3, Flipper Zero, libnfc reader). They "
        "cannot be reached from any network-based SaaS scanner.")

_TECHNIQUES = [
    ("§7 #67", "NFC tag read", "LOW", _WHY,
     "Read tags on-site with NFC Tools/libnfc; for access tokens, use "
     "cryptographically authenticated tags (DESFire EV2/3) not plain UID.",
     "CWE-319"),
    ("§7 #68", "NFC tag clone", "HIGH", _WHY,
     "Demonstrate cloning with Proxmark3/Flipper on-site; migrate from cloneable "
     "UID-only tags to challenge-response authenticated credentials.", "CWE-290"),
    ("§7 #69", "MIFARE Classic key crack (mfoc/mfcuk)", "HIGH", _WHY,
     "Crack Crypto-1 keys with mfoc/mfcuk on-site; MIFARE Classic is broken — "
     "migrate to MIFARE DESFire EV2/3 or iCLASS SE.", "CWE-327"),
    ("§7 #70", "MIFARE Classic clone", "HIGH", _WHY,
     "Clone to a magic/gen1 card with Proxmark3; same remediation — abandon "
     "MIFARE Classic for AES-authenticated credentials.", "CWE-290"),
    ("§7 #71", "NFC relay attack", "HIGH", _WHY,
     "Relay an NFC transaction with paired Proxmark3 devices; deploy proximity/"
     "timing checks and tap-to-pay transaction limits.", "CWE-294"),
    ("§7 #72", "HID Prox card clone", "HIGH", _WHY,
     "Capture+clone 125kHz HID Prox with Proxmark3; HID Prox is unencrypted — "
     "migrate to iCLASS SE / SEOS or DESFire-based access control.", "CWE-319"),
    ("§7 #73", "iCLASS / DESFire attack", "MEDIUM", _WHY,
     "Audit iCLASS legacy (broken) vs iCLASS SE / DESFire (strong) on-site; "
     "ensure diversified per-card keys and current firmware.", "CWE-327"),
    ("§7 #74", "Manual RFID social-engineering chain", "INFO", _WHY,
     "Analyst-driven, engagement-scoped physical testing; out of scope for "
     "automated SaaS scanning.", "CWE-1395"),
]

NFC_RFID_ADVISORY_FINDING_RULES = build_advisory_rules("nfc_rfid_advisory", _TECHNIQUES)
