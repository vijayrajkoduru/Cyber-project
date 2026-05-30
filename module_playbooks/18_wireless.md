# Wireless Network Attacks — Master Reference (`wireless_ruff`)

**100% Full Industry Standard catalogue** — aligned with WiFi Alliance specs + IEEE 802.11 attack canon + aircrack-ng methodology + 2024–2026 industry additions (WPA3 SAE, 6 GHz, Wi-Fi 7).

8 sections, 90 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Wi-Fi Recon / Enumeration | 12 | 10 | 2 |
| 2 | WEP / WPA / WPA2 Attacks | 14 | 11 | 3 |
| 3 | WPA3 Attacks ⭐ | 8 | 5 | 3 |
| 4 | Enterprise WiFi (WPA2-EAP) | 10 | 7 | 3 |
| 5 | Rogue AP / Evil Twin | 10 | 7 | 3 |
| 6 | Bluetooth / BLE | 12 | 9 | 3 |
| 7 | NFC / RFID | 8 | 4 | 4 |
| 8 | Cellular / 5G / SDR ⭐ | 10 | 4 | 6 |
| **TOTAL** | | **84** | **57** | **27** |

---

## §1 — Wi-Fi Recon / Enumeration

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Monitor mode + capture | airmon-ng + airodump-ng | ✅ |
| 2 | SSID + BSSID + channel list | airodump-ng | ✅ |
| 3 | Hidden SSID discovery | airodump-ng + deauth | ✅ |
| 4 | Client enum (probe requests) | airodump-ng | ✅ |
| 5 | Channel hopping scan | airodump-ng | ✅ |
| 6 | Signal strength mapping | kismet | ✅ |
| 7 | Wigle GPS lookup (war-driving) | wigle.net + kismet | ✅ |
| 8 | OUI vendor identification | macvendors.com | ✅ |
| 9 ⭐ | Wi-Fi 6 / 6E / 7 capability fingerprint | airodump-ng + custom | ✅ |
| 10 ⭐ | 6 GHz band capability detect | iw scan + custom | ✅ |
| 11 | Manual creative client tracking | analyst + kismet | 👤 |
| 12 | Manual neighbor-AP map | analyst | 👤 |

---

## §2 — WEP / WPA / WPA2 Attacks

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 13 | WEP IV collection + crack | aircrack-ng | ✅ |
| 14 | WPA/WPA2 4-way handshake capture | airodump-ng + deauth | ✅ |
| 15 | Deauthentication attack | aireplay-ng -0 | ✅ |
| 16 | PMKID capture (no client needed) | hcxdumptool | ✅ |
| 17 | WPA handshake crack (mode 22000) | hashcat | ✅ |
| 18 | wifite automated workflow | wifite | ✅ |
| 19 | WPS PIN brute (Pixie Dust) | reaver, bully | ✅ |
| 20 | WPS PIN brute (online) | reaver | ✅ |
| 21 | Krack attack (CVE-2017-13077) | manual + custom | 👤 |
| 22 | Karma attack (probe-response abuse) | manual + custom | 👤 |
| 23 | Wi-Fi covert channel | manual + custom | 👤 |
| 24 ⭐ | OneShot Pixie Dust attack | OneShot | ✅ |
| 25 | Manual handshake forensics | analyst | 👤 |
| 26 | Manual EAPOL replay attack | analyst | 👤 |

---

## §3 — WPA3 Attacks ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 27 ⭐ | Dragonblood (CVE-2019-9494) — SAE downgrade | manual + custom | ✅ |
| 28 ⭐ | SAE side-channel timing | manual + research | 👤 |
| 29 ⭐ | WPA3 downgrade to WPA2 (transition mode) | custom + airodump | ✅ |
| 30 ⭐ | EasyConnect (DPP) attack | manual + research | 👤 |
| 31 ⭐ | SAE H2E (Hash-to-Element) abuse | manual + research | ✅ |
| 32 ⭐ | WPA3-Enterprise EAP-TLS audit | manual + custom | ✅ |
| 33 ⭐ | OWE (Opportunistic Wireless Encryption) audit | custom | ✅ |
| 34 ⭐ | Manual creative WPA3 chain | analyst | 👤 |

---

## §4 — Enterprise WiFi (WPA2-EAP)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 35 | EAP-TLS cert chain audit | manual + custom | ✅ |
| 36 | EAP-PEAP / EAP-TTLS credential capture | hostapd-wpe | ✅ |
| 37 | NetNTLMv2 hash from RADIUS | hostapd-wpe + hashcat | ✅ |
| 38 | Rogue RADIUS impersonation | hostapd-wpe | ✅ |
| 39 | Evil Twin Enterprise | eaphammer | ✅ |
| 40 | EAP downgrade attack | eaphammer | ✅ |
| 41 | MSCHAPv2 challenge-response capture | hostapd-wpe + asleap | ✅ |
| 42 | 802.1X MAC-bypass test | manual + custom | 👤 |
| 43 ⭐ | Modern WPA3-Enterprise SAE-PK audit | manual + research | 👤 |
| 44 | Manual enterprise pivot chain | analyst | 👤 |

---

## §5 — Rogue AP / Evil Twin

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 45 | hostapd-wpe rogue AP | hostapd-wpe | ✅ |
| 46 | airbase-ng evil twin | airbase-ng | ✅ |
| 47 | wifiphisher automated phishing | wifiphisher | ✅ |
| 48 | Karma + captive portal injection | bettercap | ✅ |
| 49 | DHCP + DNS spoofing on rogue AP | dnsmasq + custom | ✅ |
| 50 | Forced association deauth | aireplay-ng + custom | ✅ |
| 51 | Pineapple / Wi-Fi Pineapple workflow | Pineapple | ✅ |
| 52 ⭐ | EAP-Pickle (modern enterprise evil twin) | eaphammer | ✅ |
| 53 | Manual victim-targeting strategy | analyst | 👤 |
| 54 | Manual captive portal phishing design | analyst + HTML | 👤 |

---

## §6 — Bluetooth / BLE

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 55 | BLE device enumeration | bluetoothctl, gatttool | ✅ |
| 56 | BLE service / characteristic enum | gatttool, btlejuice | ✅ |
| 57 | BLE pairing weak-key attack | btlejuice, gattacker | ✅ |
| 58 | BLE replay attack | btlejack | ✅ |
| 59 | BLE sniff (Ubertooth / nRF) | ubertooth, nrf-sniffer | ✅ |
| 60 | Bluetooth Classic SDP enum | bluetoothctl + custom | ✅ |
| 61 | Bluetooth Classic PIN brute | redfang | ✅ |
| 62 ⭐ | BlueBorne CVE-2017-0781 | manual + research | ✅ |
| 63 ⭐ | Bluetooth Impersonation (BIAS) | manual + research | 👤 |
| 64 ⭐ | Bluetooth Forward and Future Secrecy attack | manual + research | 👤 |
| 65 | BlueJacking / BlueSnarfing | bluesnarfer | 👤 |
| 66 | Manual BLE protocol RE | analyst + Wireshark | 👤 |

---

## §7 — NFC / RFID

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 67 | NFC tag read | NFC Tools, libnfc | ✅ |
| 68 | NFC tag clone | Proxmark3, Flipper Zero | ✅ |
| 69 | MIFARE Classic key crack | mfoc, mfcuk | ✅ |
| 70 | MIFARE Classic clone | Proxmark3 | ✅ |
| 71 | NFC relay attack | Proxmark3 + manual | 👤 |
| 72 | HID Prox card clone | Proxmark3 | 👤 |
| 73 | iCLASS / DESFire attack | Proxmark3 + manual | 👤 |
| 74 | Manual RFID social-eng chain | analyst | 👤 |

---

## §8 — Cellular / 5G / SDR ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 75 | IMSI catching (legacy, RTL-SDR) | OpenBTS + RTL-SDR | 👤 |
| 76 ⭐ | 5G NSA → SA downgrade | manual + research | 👤 |
| 77 ⭐ | 5G SUPI / SUCI privacy attack | manual + research | 👤 |
| 78 | SS7 / Diameter abuse (mobile core) | SigPloit | ✅ |
| 79 ⭐ | OpenAirInterface 5G testbed audit | OAI + manual | 👤 |
| 80 | ADS-B aircraft tracking | dump1090 + RTL-SDR | ✅ |
| 81 | AIS ship tracking | rtl_ais | ✅ |
| 82 ⭐ | LoRa / LoRaWAN traffic analysis | LoRa-pkt-fwd + manual | ✅ |
| 83 ⭐ | Pager / POCSAG intercept | rtl-sdr + multimon-ng | ✅ |
| 84 | Manual SDR creative attack | analyst | 👤 |

---

## Compliance Mapping
- **NIST SP 800-153 (Wireless)** · **NIST SP 800-97 (RSN/WPA2)** · **PCI DSS 4.0 §4.2.1 (wireless transmission)** · **HIPAA**

## VulnusLab Wireless Status
- Status: 🟡 SOON (per modules_2026_inventory.md #17)
- Planned scanners: List Interfaces, Network Scan, Deauth Attack, Auto Attack (wifite), Crack Handshake (aircrack-ng)
- Coverage: ~0% (UI placeholder)

## Roadmap to 100%
1. Phase W-1: §1 Wi-Fi recon (12 scanners — wrap airodump/kismet)
2. Phase W-2: §2 WPA/WPA2 attacks (14 — wrap aircrack-ng + hashcat + wifite)
3. Phase W-3: §3 WPA3 ⭐ + §4 Enterprise (18 ⭐)
4. Phase W-4: §5 rogue AP / evil twin (10)
5. Phase W-5: §6 Bluetooth (12)
6. Phase W-6: §7 NFC/RFID (8 — niche, requires Proxmark hardware)
7. Phase W-7: §8 Cellular/SDR (10, mostly manual)

## References
- aircrack-ng: https://www.aircrack-ng.org/
- hcxdumptool / hcxtools: https://github.com/ZerBea/hcxdumptool
- wifite: https://github.com/derv82/wifite2
- eaphammer: https://github.com/s0lst1c3/eaphammer
- hostapd-wpe: https://github.com/OpenSecurityResearch/hostapd-wpe
- bettercap: https://www.bettercap.org/
- Proxmark3: https://github.com/RfidResearchGroup/proxmark3
- Flipper Zero: https://flipperzero.one/
