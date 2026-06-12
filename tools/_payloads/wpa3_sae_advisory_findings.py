"""wpa3_sae_advisory - findings rules (playbook §3 #27-34).

All INFO / advisory-by-design. WPA3 SAE attacks require monitor-mode RF capture
and on-air frame injection adjacent to the target BSS — not SaaS-probeable.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("WPA3/SAE attacks operate on 802.11 management/EAPOL frames captured in "
        "monitor mode adjacent to the target access point.")

_TECHNIQUES = [
    ("§3 #27", "Dragonblood SAE downgrade (CVE-2019-9494)", "HIGH", _WHY,
     "On a monitor-mode adapter near the AP, capture the SAE commit/confirm "
     "exchange and test for transition-mode downgrade to WPA2; patch APs to "
     "firmware addressing CVE-2019-9494/9496.", "CWE-326"),
    ("§3 #28", "SAE side-channel timing leak", "MEDIUM", _WHY,
     "Measure SAE handshake timing variance with an on-air capture rig; deploy "
     "Hash-to-Element (H2E) which is constant-time and disable the legacy "
     "hunting-and-pecking group exchange.", "CWE-208"),
    ("§3 #29", "WPA3->WPA2 transition-mode downgrade", "HIGH", _WHY,
     "Capture beacons with airodump-ng to confirm transition mode is advertised, "
     "then verify a WPA2 association is still accepted; move to WPA3-only where "
     "client support allows.", "CWE-757"),
    ("§3 #30", "EasyConnect (DPP) provisioning abuse", "MEDIUM", _WHY,
     "Inspect DPP bootstrapping (QR/PKEX) on-site; restrict DPP enrollee "
     "provisioning windows and validate bootstrap public keys.", "CWE-287"),
    ("§3 #31", "SAE H2E (Hash-to-Element) abuse", "MEDIUM", _WHY,
     "Analyze the negotiated SAE group/method in a live capture; keep AP firmware "
     "current and require PMF (802.11w).", "CWE-326"),
    ("§3 #33", "OWE (Opportunistic Wireless Encryption) audit", "LOW", _WHY,
     "Confirm open/OWE networks advertise the OWE transition correctly and that "
     "a downgrade to a fully-open BSS is not silently accepted.", "CWE-319"),
    ("§3 #32", "WPA3-Enterprise EAP-TLS posture (on-air)", "MEDIUM", _WHY,
     "Audit the EAP-TLS exchange with a RADIUS-adjacent capture; pin server "
     "certificate validation on supplicants and require PMF.", "CWE-295"),
    ("§3 #34", "Manual creative WPA3 attack chain", "INFO", _WHY,
     "Analyst-driven, engagement-scoped manual testing on the target LAN; "
     "out of scope for automated SaaS scanning.", "CWE-1395"),
]

WPA3_SAE_ADVISORY_FINDING_RULES = build_advisory_rules("wpa3_advisory", _TECHNIQUES)
