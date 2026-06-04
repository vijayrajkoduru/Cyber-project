"""§18 Wireless — 57 endpoints per 18_wireless.md.
8 sections: WiFi recon, WEP/WPA/WPA2, WPA3, enterprise EAP, evil twin,
BT/BLE, NFC/RFID, cellular/SDR.
"""
from tools._pack_common import make_advisory_router

T = [
    # §1 WiFi Recon (10)
    ("airodump_ng", "airodump-ng survey.", "INFO", "0.0"),
    ("kismet_advisory", "kismet wireless survey.", "INFO", "0.0"),
    ("wifite_advisory", "wifite automated wireless.", "MEDIUM", "5.0"),
    ("iwlist_scan", "iwlist scan.", "INFO", "0.0"),
    ("wash_wps_detect", "wash WPS detect.", "MEDIUM", "5.5"),
    ("kismon_advisory", "Kismon GUI.", "INFO", "0.0"),
    ("wigle_geosearch", "WiGLE geosearch.", "INFO", "0.0"),
    ("wifi_channel_hopping", "Channel hopping enumeration.", "INFO", "0.0"),
    ("hidden_ssid_uncover", "Hidden SSID uncover (deauth).", "MEDIUM", "5.5"),
    ("client_mac_collect", "Client MAC collection.", "INFO", "0.0"),
    # §2 WEP/WPA/WPA2 (11)
    ("wep_iv_attack_aircrack", "WEP IV attack (aircrack-ng).", "CRITICAL", "9.0"),
    ("wep_chopchop", "WEP ChopChop attack.", "CRITICAL", "9.0"),
    ("wep_fragmentation", "WEP fragmentation attack.", "CRITICAL", "9.0"),
    ("wpa2_handshake_capture", "WPA2 4-way handshake capture.", "HIGH", "7.0"),
    ("wpa2_hashcat_crack", "WPA2 hashcat -m 22000.", "HIGH", "7.5"),
    ("wpa2_pmkid_attack", "WPA2 PMKID attack (no client).", "HIGH", "7.5"),
    ("wpa2_krack", "WPA2 KRACK (CVE-2017-13077).", "HIGH", "7.0"),
    ("wps_pin_reaver", "WPS PIN reaver brute.", "HIGH", "8.0"),
    ("wps_pixie_dust", "WPS Pixie Dust attack.", "HIGH", "8.0"),
    ("wps_null_pin", "WPS NULL PIN attack.", "HIGH", "7.5"),
    ("deauth_dos_aireplay", "Deauth DoS (aireplay-ng).", "HIGH", "7.0"),
    # §3 WPA3 (5)
    ("wpa3_dragonblood_advisory", "WPA3 Dragonblood advisory.", "MEDIUM", "5.5"),
    ("wpa3_downgrade_attack", "WPA3 downgrade to WPA2 attack.", "HIGH", "7.5"),
    ("wpa3_sae_h2e_audit", "WPA3 SAE H2E audit.", "MEDIUM", "5.5"),
    ("wpa3_transition_mode_audit", "WPA3 transition mode audit.", "MEDIUM", "5.5"),
    ("manual_wpa3_chain", "Manual WPA3 chain.", "INFO", "0.0"),
    # §4 Enterprise WiFi WPA2-EAP (7)
    ("eaphammer_rogue_ap", "EAPHammer rogue AP attack.", "HIGH", "8.0"),
    ("hostapd_wpe_advisory", "hostapd-wpe (WiFi Pineapple).", "HIGH", "8.0"),
    ("eap_relay_attack", "EAP relay attack.", "HIGH", "8.0"),
    ("eap_md5_crack", "EAP-MD5 crack.", "HIGH", "7.5"),
    ("eap_peap_relay", "EAP-PEAP relay.", "HIGH", "8.0"),
    ("eap_ttls_crack", "EAP-TTLS crack.", "HIGH", "7.5"),
    ("radius_certificate_audit", "RADIUS certificate audit.", "MEDIUM", "5.5"),
    # §5 Rogue AP / Evil Twin (7)
    ("airbase_ng_rogue_ap", "airbase-ng rogue AP.", "HIGH", "7.5"),
    ("fluxion_advisory", "Fluxion evil twin.", "HIGH", "8.0"),
    ("wifiphisher_advisory", "wifiphisher.", "HIGH", "8.0"),
    ("karma_attack_advisory", "Karma attack (probe response).", "HIGH", "8.0"),
    ("captive_portal_phishing", "Captive portal phishing.", "HIGH", "7.5"),
    ("evil_twin_with_aitm", "Evil twin + AiTM.", "CRITICAL", "9.0"),
    ("manual_evil_twin_chain", "Manual evil twin chain.", "INFO", "0.0"),
    # §6 Bluetooth / BLE (9)
    ("bluetoothctl_scan", "bluetoothctl scan.", "INFO", "0.0"),
    ("hcitool_inquiry", "hcitool inquiry.", "INFO", "0.0"),
    ("bettercap_ble_recon", "bettercap BLE recon.", "INFO", "0.0"),
    ("gatttool_enum", "gatttool GATT enumeration.", "MEDIUM", "5.5"),
    ("btlejuice_mitm", "btlejuice BLE MITM.", "HIGH", "7.5"),
    ("gattacker_mitm", "gattacker BLE MITM.", "HIGH", "7.5"),
    ("crackle_ble_pairing", "crackle BLE pairing crack.", "HIGH", "7.5"),
    ("bluesnarf_bluebugging", "BlueSnarf / BlueBugging.", "HIGH", "7.5"),
    ("blueborne_cve_advisory", "BlueBorne CVE advisory.", "HIGH", "8.0"),
    # §7 NFC / RFID (4)
    ("proxmark3_advisory", "Proxmark3 NFC/RFID.", "HIGH", "7.5"),
    ("mfoc_mifare_classic", "mfoc MIFARE Classic crack.", "HIGH", "7.5"),
    ("nfc_relay_attack", "NFC relay attack.", "HIGH", "7.5"),
    ("rfid_clone_advisory", "RFID clone advisory.", "HIGH", "7.5"),
    # §8 Cellular / 5G / SDR (4)
    ("imsi_catcher_advisory", "IMSI catcher (stingray) advisory.", "HIGH", "7.5"),
    ("hackrf_sdr_advisory", "HackRF SDR advisory.", "MEDIUM", "5.5"),
    ("yatebts_open5gs_advisory", "YateBTS / Open5GS advisory.", "MEDIUM", "5.5"),
    ("ss7_diameter_research", "SS7/Diameter research advisory.", "MEDIUM", "5.5"),
]

router = make_advisory_router("wireless", T,
    playbook_ref="See module_playbooks/18_wireless.md.")


def register(app):
    app.include_router(router)
