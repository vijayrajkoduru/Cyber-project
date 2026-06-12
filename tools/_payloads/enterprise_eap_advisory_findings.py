"""enterprise_eap_advisory - findings rules (playbook §4 #35-44).

All INFO / advisory-by-design. Enterprise EAP attacks require a rogue AP +
rogue RADIUS on the target RF to capture client supplicant credentials.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("Enterprise EAP credential capture requires standing up a rogue access "
        "point and rogue RADIUS server adjacent to the target's RF and luring "
        "client supplicants — active impersonation with physical proximity.")

_TECHNIQUES = [
    ("§4 #35", "EAP-TLS certificate-chain audit", "MEDIUM", _WHY,
     "On the target RF, present a rogue RADIUS and observe whether supplicants "
     "validate the server cert/CA; enforce server-cert + CA pinning on all "
     "supplicants and disable 'do not validate certificate'.", "CWE-295"),
    ("§4 #36", "EAP-PEAP / EAP-TTLS credential capture (hostapd-wpe)", "HIGH", _WHY,
     "Run hostapd-wpe as a rogue AP to capture inner-tunnel credentials; mandate "
     "server-cert validation + a strong, unique RADIUS CA so rogue APs are "
     "rejected.", "CWE-522"),
    ("§4 #37", "NetNTLMv2 hash harvest from RADIUS", "HIGH", _WHY,
     "Capture MSCHAPv2 challenge/response via rogue RADIUS and crack offline; "
     "move to EAP-TLS (certificate-based) which has no crackable inner secret.",
     "CWE-916"),
    ("§4 #38", "Rogue RADIUS impersonation", "HIGH", _WHY,
     "Impersonate the RADIUS endpoint to a connecting client; enforce mutual "
     "TLS and supplicant-side CA pinning.", "CWE-290"),
    ("§4 #39", "Evil Twin Enterprise (eaphammer)", "HIGH", _WHY,
     "Clone the enterprise SSID with eaphammer and capture EAP relay creds; "
     "deploy PMF (802.11w) + server-cert validation; monitor for duplicate "
     "BSSIDs with a WIDS.", "CWE-290"),
    ("§4 #40", "EAP downgrade attack", "MEDIUM", _WHY,
     "Force a weaker EAP method via rogue AP negotiation; restrict allowed EAP "
     "methods on the supplicant to EAP-TLS only.", "CWE-757"),
    ("§4 #41", "MSCHAPv2 challenge-response capture", "HIGH", _WHY,
     "Capture and crack MSCHAPv2 with asleap/hashcat; abandon PEAP-MSCHAPv2 in "
     "favor of EAP-TLS.", "CWE-916"),
    ("§4 #42", "802.1X MAC-authentication-bypass test", "MEDIUM", _WHY,
     "Spoof an allow-listed device MAC on the wire/RF to bypass MAB; pair MAB "
     "with profiling/posture and avoid MAB on sensitive segments.", "CWE-290"),
    ("§4 #43", "WPA3-Enterprise SAE-PK audit", "MEDIUM", _WHY,
     "Audit SAE-PK public-key provisioning on-site; keep AP/controller firmware "
     "current and require PMF.", "CWE-295"),
    ("§4 #44", "Manual enterprise pivot chain", "INFO", _WHY,
     "Analyst-driven, engagement-scoped post-foothold testing; out of scope for "
     "automated SaaS scanning.", "CWE-1395"),
]

ENTERPRISE_EAP_ADVISORY_FINDING_RULES = build_advisory_rules(
    "enterprise_eap_advisory", _TECHNIQUES)
