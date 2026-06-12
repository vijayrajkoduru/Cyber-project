"""cellular_sdr_advisory - findings rules (playbook §8 #75-84).

All INFO / advisory-by-design. Cellular/SDR techniques require RF hardware
(RTL-SDR/HackRF), proximity, and frequently a licensed/legal testbed; several
involve legally restricted transmission. Not SaaS-probeable.
"""
from tools._payloads._wireless_advisory_common import build_advisory_rules

_WHY = ("Cellular/5G/SDR techniques require RF hardware (RTL-SDR, HackRF, "
        "BladeRF), physical RF proximity, and often a licensed/legal testbed; "
        "transmitting on cellular bands is legally restricted. None is "
        "reachable from an external SaaS scanner.")

_TECHNIQUES = [
    ("§8 #75", "IMSI catching (legacy, RTL-SDR)", "HIGH", _WHY,
     "Operate a controlled OpenBTS/srsRAN testbed under license; defend with "
     "5G SUCI concealment + downgrade detection on managed handsets.", "CWE-359"),
    ("§8 #76", "5G NSA -> SA downgrade", "HIGH", _WHY,
     "Test downgrade resistance in a licensed 5G testbed; deploy SA-only "
     "policies + downgrade alerts where the network supports it.", "CWE-757"),
    ("§8 #77", "5G SUPI / SUCI privacy attack", "MEDIUM", _WHY,
     "Audit SUCI concealment in a testbed; ensure home-network public-key "
     "provisioning is enforced so the SUPI is never sent in clear.", "CWE-359"),
    ("§8 #78", "SS7 / Diameter abuse (mobile core)", "CRITICAL", _WHY,
     "Requires SS7/Diameter interconnect access (SigPloit) — carrier-side only; "
     "defend with signaling firewalls + GSMA FS.11/FS.19 monitoring.", "CWE-284"),
    ("§8 #79", "OpenAirInterface 5G testbed audit", "MEDIUM", _WHY,
     "Stand up an OAI lab to audit gNB/AMF config; harden per 3GPP security "
     "baselines.", "CWE-1188"),
    ("§8 #80", "ADS-B aircraft tracking (passive)", "LOW", _WHY,
     "Passive receive-only with dump1090 + RTL-SDR; informational — ADS-B is "
     "unauthenticated by design (mitigated by multilateration + future ADS-B "
     "auth).", "CWE-319"),
    ("§8 #81", "AIS ship tracking (passive)", "LOW", _WHY,
     "Passive receive-only with rtl_ais; informational — AIS is unauthenticated "
     "by design.", "CWE-319"),
    ("§8 #82", "LoRa / LoRaWAN traffic analysis", "MEDIUM", _WHY,
     "Capture LoRa frames on-site; enforce LoRaWAN 1.1 with rotated AppKey/"
     "NwkKey and join-server security.", "CWE-319"),
    ("§8 #83", "Pager / POCSAG intercept (passive)", "MEDIUM", _WHY,
     "Passive receive with rtl-sdr + multimon-ng; POCSAG is plaintext — stop "
     "sending sensitive data over pagers.", "CWE-319"),
    ("§8 #84", "Manual SDR creative attack", "INFO", _WHY,
     "Analyst-driven, engagement-scoped RF research; out of scope for automated "
     "SaaS scanning.", "CWE-1395"),
]

CELLULAR_SDR_ADVISORY_FINDING_RULES = build_advisory_rules(
    "cellular_sdr_advisory", _TECHNIQUES)
