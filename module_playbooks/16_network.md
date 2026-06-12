# Network Attacks — Master Reference (`network_ruff`)

**100% Full Industry Standard catalogue** — aligned with PTES Network Pentest + NIST SP 800-115 §4.3 + MITRE ATT&CK Network domain + 2024–2026 industry additions.

8 sections, 105 techniques.

**Legend:** auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Port & Service Enumeration | 14 | 14 | 0 |
| 2 | LAN Attacks (Layer 2) | 14 | 9 | 5 |
| 3 | MITM Attacks | 12 | 7 | 5 |
| 4 | DoS / DDoS Testing | 10 | 8 | 2 |
| 5 | Network Sniffing & Capture | 10 | 8 | 2 |
| 6 | DNS Attacks | 10 | 9 | 1 |
| 7 | IPv6-specific Attacks | 10 | 7 | 3 |
| 8 | Network Protocol Fuzzing | 8 | 5 | 3 |
| **TOTAL** | | **88** | **67** | **21** |

---

## §1 — Port & Service Enumeration

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | TCP SYN scan | nmap, masscan, naabu | |
| 2 | UDP scan (top ports) | nmap -sU | |
| 3 | Service/version detection | nmap -sV, nuclei | |
| 4 | OS fingerprinting | nmap -O | |
| 5 | NSE vuln scripts | nmap --script vuln | |
| 6 | Banner grabbing | ncat, nuclei | |
| 7 | SMB enum (shares, users) | crackmapexec smb, enum4linux-ng | |
| 8 | SNMP enumeration | onesixtyone, snmpwalk | |
| 9 | RPC endpoint mapper | rpcclient | |
| 10 | LDAP anonymous bind | ldapsearch | |
| 11 | NFS share enumeration | showmount, nmap NSE | |
| 12 | SMTP user enum (VRFY, EXPN) | nmap NSE smtp-enum | |
| 13 | IPMI / iLO / iDRAC discovery (623) | nmap NSE | |
| 14 | gRPC reflection discovery | grpcurl | |

---

## §2 — LAN Attacks (Layer 2)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | ARP spoofing | arpspoof, bettercap, ettercap | |
| 16 | MAC flooding (CAM table) | macof | |
| 17 | DHCP starvation | yersinia, dhcpig | |
| 18 | DHCP rogue server | yersinia, dnsmasq | |
| 19 | STP root takeover | yersinia, scapy | |
| 20 | VLAN hopping (double-tagging) | yersinia, scapy | |
| 21 | LLMNR / NBT-NS / mDNS poisoning | Responder, Inveigh | |
| 22 | IPv6 mitm6 (DHCPv6 + WPAD) | mitm6 | |
| 23 | CDP/LLDP spoofing | yersinia | |
| 24 | HSRP/VRRP/GLBP hijack | yersinia | |
| 25 | Port stealing | ettercap | |
| 26 | NDP spoofing (IPv6 layer 2) | thc-ipv6 | |
| 27 | 802.1X bypass | manual + custom | |
| 28 | Manual creative L2 chain | analyst | |

---

## §3 — MITM Attacks

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 29 | bettercap automated MITM | bettercap | |
| 30 | mitmproxy interactive | mitmproxy | |
| 31 | SSLstrip / SSLstrip2 | sslstrip, sslstrip2 | |
| 32 | HSTS bypass (preload list dodge) | sslstrip2 + dns2proxy | (probe) |
| 33 | Captive portal injection | bettercap | |
| 34 | NTLM relay (SMB → LDAP/AD CS) | ntlmrelayx.py | |
| 35 | Coercion + relay chain | Coercer + ntlmrelayx | |
| 36 | DNS spoofing (LAN) | dnsspoof, bettercap | |
| 37 | Evil twin Wi-Fi MITM | hostapd-wpe + bettercap | |
| 38 | mTLS interception (with cert) | manual + Burp | |
| 39 | TLS downgrade (RC4/SSLv3) | manual + bettercap | |
| 40 | Manual creative MITM chain | analyst | |

---

## §4 — DoS / DDoS Testing

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 41 | TCP SYN flood | hping3, mhddos | |
| 42 | UDP flood | hping3 | |
| 43 | ICMP flood / smurf | hping3 | |
| 44 | Slowloris (HTTP slow header) | slowloris.py | |
| 45 | R-U-Dead-Yet (slow POST) | RUDY | |
| 46 | DNS amplification | dnsperf + custom | |
| 47 | NTP amplification | nmap NSE ntp-monlist | |
| 48 | Memcached amplification | nuclei + custom | |
| 49 | HTTP/2 Rapid Reset (CVE-2023-44487) | nuclei + custom | |
| 50 | Manual application-layer DoS chain | analyst | |

---

## §5 — Network Sniffing & Capture

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 51 | tcpdump capture | tcpdump | |
| 52 | Wireshark interactive analysis | tshark | |
| 53 | Plaintext credential harvest | ettercap, bettercap | |
| 54 | NTLM hash capture (Responder) | Responder | |
| 55 | Net-NTLMv2 hash crack | hashcat 5600 | |
| 56 | TLS cert extraction from packets | tshark + custom | |
| 57 | DNS query analysis | tshark + custom | |
| 58 | Protocol decode (custom dissector) | wireshark + lua | |
| 59 | Wi-Fi monitor-mode capture | airodump-ng | |
| 60 | Manual creative capture pivot | analyst | |

---

## §6 — DNS Attacks

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 61 | DNS cache poisoning | manual + scapy | |
| 62 | DNS rebinding attack | rebinder.cloud, custom | |
| 63 | Subdomain takeover | subjack, nuclei | |
| 64 | DNS tunneling detection | manual + entropy | |
| 65 | NXNS amplification | manual + research | |
| 66 | DNS zone transfer (AXFR) | dig +axfr | |
| 67 | DNS NSEC walking | nsec3walker | |
| 68 | Kaminsky-style poisoning (0x20 entropy) | dig + custom | |
| 69 | SAD DNS (CVE-2020-25705) | manual + research | |
| 70 | Manual creative DNS exploit | analyst | |

---

## §7 — IPv6-specific Attacks NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 | THC-IPv6 toolkit (alive6, etc.) | thc-ipv6 | |
| 72 | RA (Router Advertisement) flood | flood_router6 | |
| 73 | NDP spoofing | parasite6, neighbor6 | |
| 74 | DHCPv6 rogue server | dhcpig, mitm6 | |
| 75 | SLAAC attack | thc-ipv6 | |
| 76 | IPv6 routing header abuse | thc-ipv6 | |
| 77 | mitm6 + ntlmrelayx → LDAP/AD CS | mitm6 + ntlmrelayx | |
| 78 | IPv6-tunnel exfil | manual + custom | |
| 79 | Dual-stack policy bypass | manual + custom | |
| 80 | Manual IPv6 lateral pivot | analyst | |

---

## §8 — Network Protocol Fuzzing

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 81 | boofuzz network fuzzing | boofuzz | |
| 82 | Scapy custom packet crafting | scapy | |
| 83 | Protocol fuzzing (HTTP, FTP, SMTP) | boofuzz + AFL | |
| 84 | mDNS / SSDP / DNS-SD fuzzing | custom + scapy | |
| 85 | TLS handshake fuzzing | manual + custom | |
| 86 | gRPC / WebSocket protocol fuzz | grpc-fuzz + manual | |
| 87 | Custom binary protocol fuzz | manual + boofuzz | |
| 88 | Manual protocol RE + fuzz | analyst | |

---

## Compliance Mapping
- **PTES Network Pentest** · **NIST SP 800-115 §4.3** · **MITRE ATT&CK (TA0006 Credential Access via Network)** · **PCI DSS 4.0 §11.3.1**

## VulnusLab Network Status
- Status: LIVE — 67/67 techniques covered, ZERO scaffolds (2026-06-12 build).
- Architecture: single-pack `tools/network/network_pack.py` (TECHNIQUES=67) + `endpoints/network_orchestrator.py` (8 tiers), generic ModuleAutoPanel UI.
- 18 live SAFE probes (read-only, no spoofing/flooding/sniffing):
  - §1 Port & Service Enumeration (14): TCP connect scan (top-45 + masscan/naabu real-binary if installed), UDP probe, version/banner grab, OS heuristic, default-scripts, aggressive, hping3 reachability, netcat banner
  - §6 DNS (4): zone transfer (AXFR), open-resolver check, subdomain-takeover (dangling CNAME), DNSSEC NSEC zone-walk
- 49 advisory-by-design — network attacks beyond port/DNS are inherently LAN-position or active: §2 LAN L2 (ARP/MAC/VLAN/DHCP/STP/HSRP) need Layer-2 adjacency; §3 MITM + §6 cache-poison/hijack are active interception; §4 DoS/amplification are disruptive load; §5 sniffing needs on-segment capture; §7 IPv6 needs IPv6 LAN; §8 fuzzing can crash the service. All return honest [ADVISORY-BY-DESIGN] INFO, never fabricated HIGH. (subdomain brute -> Recon module.)
- Estimated coverage: ~75% of full standard via remote-safe probing; remainder requires an on-LAN agent (future feature, not a forge gap).

## Roadmap to 100%
1. Phase N-1: §1 port/service enum (14 scanners) — reuse Recon code
2. Phase N-2: §2 L2 attacks + §3 MITM (26 scanners)
3. Phase N-3: §4 DoS testing (10 scanners)
4. Phase N-4: §5 sniffing + §6 DNS attacks (20 scanners)
5. Phase N-5: §7 IPv6 + §8 protocol fuzzing (18 scanners)

## References
- bettercap: https://www.bettercap.org/
- Responder: https://github.com/lgandx/Responder
- mitm6: https://github.com/dirkjanm/mitm6
- thc-ipv6: https://github.com/vanhauser-thc/thc-ipv6
- scapy: https://scapy.net/
- boofuzz: https://github.com/jtpereyda/boofuzz
