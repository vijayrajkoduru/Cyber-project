# IoT / OT / ICS Security — Master Reference (`iot_ot_ruff`)

**100% Full Industry Standard catalogue** — aligned with IEC 62443 + NIST SP 800-82 + Dragos / Claroty / Nozomi research + ICS-CERT advisories + 2024–2026 industry additions.

8 sections, 90 techniques. auto · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | ICS / SCADA Discovery | 12 | 11 | 1 |
| 2 | Modbus / DNP3 / EtherNet/IP | 10 | 8 | 2 |
| 3 | Siemens S7 / Schneider / Rockwell | 10 | 7 | 3 |
| 4 | BACnet / KNX / LonWorks (Building) | 8 | 6 | 2 |
| 5 | IoT Device Recon | 14 | 13 | 1 |
| 6 | Zigbee / Z-Wave / Thread | 10 | 5 | 5 |
| 7 | Matter / Smart Home (2024+) | 8 | 4 | 4 |
| 8 | OT Pentest Methodology / Safety | 10 | 4 | 6 |
| **TOTAL** | | **82** | **58** | **24** |

---

## §1 — ICS / SCADA Discovery
1 PLCscan multi-protocol · 2 ICS-Scan Industrial Scanner · 3 nmap-ics scripts · 4 Shodan ICS filters · 5 Censys ICS filters · 6 Dragos Neighborhood Watch · 7 Nessus ICS plugin · 8 Modbus port 502 enum · 9 DNP3 port 20000 enum · 10 EtherNet/IP port 44818 enum · 11 OPC UA port 4840 enum · 12 Manual creative ICS recon

## §2 — Modbus / DNP3 / EtherNet/IP
13 Modbus function-code enum · 14 Modbus register read/write · 15 mbtget Modbus tool · 16 modpoll Modbus · 17 DNP3 outstation enum · 18 isf (Industrial Security Framework) · 19 EtherNet/IP CIP enum · 20 Modbus replay attack · 21 Manual creative ICS protocol fuzz · 22 Manual industrial-process disruption simulation

## §3 — Siemens S7 / Schneider / Rockwell
23 Snap7 S7comm client · 24 PLCBlaster (S7-1200/1500 PoC) · 25 S7 PLC time/date manipulation · 26 Schneider Modicon Modbus · 27 Rockwell ControlLogix EtherNet/IP · 28 Wago PLC enum · 29 GE iFIX HMI fuzz · 30 Manual vendor-specific firmware RE · 31 Manual creative PLC ladder-logic analysis · 32 Manual creative ICS chain

## §4 — BACnet / KNX / LonWorks (Building)
33 BACnet whois/iam scan · 34 BACnet port 47808 enum · 35 KNXmap (KNX bus scan) · 36 LonWorks discovery · 37 Building automation HMI enum · 38 Manual creative BACnet replay · 39 Manual HVAC manipulation · 40 Manual elevator / access-control test

## §5 — IoT Device Recon
41 Shodan IoT filters · 42 Censys IoT filters · 43 UPnP / SSDP discovery · 44 mDNS / Bonjour scan · 45 Default credential check (default-creds DB) · 46 IoT-specific Nuclei templates · 47 Telnet / SSH default creds · 48 MQTT broker enum (port 1883 / 8883) · 49 CoAP discovery (port 5683) · 50 AMQP broker enum · 51 OPC UA security audit · 52 HomeKit / Google Home / Alexa device fingerprint · 53 Tasmota / ESPHome / OpenHAB enum · 54 Manual creative IoT recon

## §6 — Zigbee / Z-Wave / Thread
55 KillerBee Zigbee toolkit · 56 ZBOSS Zigbee scanner · 57 Z-Force Z-Wave attack · 58 HomeMatic / Hue / SmartThings audit · 59 Zigbee NWK key extraction · 60 Replay Zigbee command · 61 Manual Zigbee channel sniff · 62 Manual Z-Wave decap · 63 Manual Thread network audit · 64 Manual creative RF analysis

## §7 — Matter / Smart Home (2024+) NEW
65 Matter protocol fingerprint · 66 Matter commissioning audit · 67 Matter security session audit · 68 Thread border-router enum · 69 chip-tool Matter CLI · 70 Manual Matter PoC · 71 Manual smart-home pivot chain · 72 Manual creative Matter abuse

## §8 — OT Pentest Methodology / Safety
73 ICS engagement scope + safety review · 74 IT vs OT network segregation audit · 75 Industrial firewall (Tofino, etc.) audit · 76 Process-aware test plan · 77 Engineering workstation forensics · 78 SCADA HMI security review · 79 Historian database audit · 80 Manual creative safety-system bypass · 81 Manual incident-response plan validation · 82 Manual creative OT pentest

---

## Compliance Mapping
- **IEC 62443** · **NIST SP 800-82 r3 (ICS Security)** · **NIST CSF (Manufacturing profile)** · **NIS2 (EU critical infra)** · **ENISA OT guidance**

## VulnusLab Status
- MISSING (module #30 in inventory) · Priority: P2 (industrial customers only)
- Coverage: 0%

## References
- Dragos: https://www.dragos.com/ · Claroty: https://claroty.com/ · Nozomi Networks: https://www.nozominetworks.com/ · isf (Industrial Security Framework): https://github.com/dark-lbp/isf · plcscan: https://github.com/meeas/plcscan · KillerBee: https://github.com/riverloopsec/killerbee · KNXmap: https://github.com/takeshixx/knxmap · Matter spec: https://csa-iot.org/all-solutions/matter/
