# Metasploit Framework — Master Reference (`metasploit_ruff`)

**100% Full Industry Standard catalogue** — aligned with Rapid7 Metasploit Pro documentation + msfconsole canon + OSCP/OSEP methodology + 2024–2026 industry additions.

8 sections, 70 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Auxiliary Modules (Recon + Scan) | 10 | 10 | 0 |
| 2 | Exploit Modules | 12 | 11 | 1 |
| 3 | Payload Modules | 10 | 9 | 1 |
| 4 | Post-Exploitation Modules | 12 | 10 | 2 |
| 5 | Encoder / Evasion | 8 | 6 | 2 |
| 6 | Database Integration | 6 | 6 | 0 |
| 7 | Meterpreter Operations | 12 | 10 | 2 |
| 8 | Modern AV/EDR Evasion (msfvenom) ⭐ | 8 | 5 | 3 |
| **TOTAL** | | **78** | **67** | **11** |

---

## §1 — Auxiliary Modules (Recon + Scan)

| # | Technique | Module | Auto? |
|---|---|---|---|
| 1 | TCP port scanner | auxiliary/scanner/portscan/tcp | ✅ |
| 2 | HTTP version detect | auxiliary/scanner/http/http_version | ✅ |
| 3 | SMB MS17-010 vuln scan | auxiliary/scanner/smb/smb_ms17_010 | ✅ |
| 4 | SSH login brute | auxiliary/scanner/ssh/ssh_login | ✅ |
| 5 | MySQL login brute | auxiliary/scanner/mysql/mysql_login | ✅ |
| 6 | HTTP directory scanner | auxiliary/scanner/http/dir_scanner | ✅ |
| 7 | Microsoft Exchange vuln scan | auxiliary/scanner/http/exchange_proxylogon | ✅ |
| 8 | Active Directory enum | auxiliary/scanner/ldap/* | ✅ |
| 9 | Heartbleed detector | auxiliary/scanner/ssl/openssl_heartbleed | ✅ |
| 10 | RDP BlueKeep scanner | auxiliary/scanner/rdp/cve_2019_0708_bluekeep | ✅ |

---

## §2 — Exploit Modules

| # | Technique | Module | Auto? |
|---|---|---|---|
| 11 | EternalBlue SMB RCE | exploit/windows/smb/ms17_010_eternalblue | ✅ |
| 12 | vsftpd 2.3.4 backdoor | exploit/unix/ftp/vsftpd_234_backdoor | ✅ |
| 13 | Rejetto HFS RCE | exploit/windows/http/rejetto_hfs_exec | ✅ |
| 14 | Apache Struts2 OGNL | exploit/multi/http/struts2_* | ✅ |
| 15 | Log4Shell | exploit/multi/http/log4shell_header_injection | ✅ |
| 16 | ProxyLogon | exploit/windows/http/exchange_proxylogon_rce | ✅ |
| 17 | ProxyShell | exploit/windows/http/exchange_proxyshell_rce | ✅ |
| 18 | PrintNightmare | exploit/windows/dcerpc/cve_2021_1675_printnightmare | ✅ |
| 19 | Spring4Shell | exploit/multi/http/spring_framework_rce_spring4shell | ✅ |
| 20 ⭐ | Veeam Backup CVE-2024-* | exploit/multi/http/veeam_* | ✅ |
| 21 ⭐ | VMware ESXi CVE chain | exploit/multi/http/vmware_* | ✅ |
| 22 | Multi-handler (catch-all reverse) | exploit/multi/handler | 👤 |

---

## §3 — Payload Modules

| # | Technique | Module | Auto? |
|---|---|---|---|
| 23 | Windows Meterpreter reverse_tcp | windows/x64/meterpreter/reverse_tcp | ✅ |
| 24 | Linux Meterpreter reverse_tcp | linux/x64/meterpreter/reverse_tcp | ✅ |
| 25 | macOS Meterpreter | osx/x64/meterpreter/reverse_tcp | ✅ |
| 26 | Windows bind_tcp | windows/x64/meterpreter/bind_tcp | ✅ |
| 27 | HTTPS Meterpreter (cert-pinned) | windows/x64/meterpreter/reverse_https | ✅ |
| 28 | Staged vs stageless variants | stage* / msfvenom -p | ✅ |
| 29 | Shellcode generation (raw) | msfvenom -p ... -f raw | ✅ |
| 30 | Multiple encoders chain | msfvenom -e shikata-ga-nai -i N | ✅ |
| 31 | Custom encoder template | msfvenom -x template.exe | ✅ |
| 32 | Manual creative payload chain | analyst | 👤 |

---

## §4 — Post-Exploitation Modules

| # | Technique | Module | Auto? |
|---|---|---|---|
| 33 | Local exploit suggester | post/multi/recon/local_exploit_suggester | ✅ |
| 34 | Linux gather/enum_system | post/linux/gather/enum_system | ✅ |
| 35 | Windows gather/credentials | post/windows/gather/credentials/* | ✅ |
| 36 | Windows gather/hashdump | post/windows/gather/hashdump | ✅ |
| 37 | Mimikatz module (kiwi) | post/windows/gather/kiwi | ✅ |
| 38 | Smart hashdump | post/windows/gather/smart_hashdump | ✅ |
| 39 | Persistence (service install) | post/windows/manage/persistence_exe | ✅ |
| 40 | Privilege escalation: getsystem | meterpreter getsystem | ✅ |
| 41 | Token impersonation | post/windows/escalate/golden_ticket | ✅ |
| 42 | Linux post-exploitation (enum) | post/linux/gather/enum_* | ✅ |
| 43 | Manual creative post-ex chain | analyst | 👤 |
| 44 | Manual lateral pivot via Meterpreter | analyst | 👤 |

---

## §5 — Encoder / Evasion

| # | Technique | Module | Auto? |
|---|---|---|---|
| 45 | shikata-ga-nai polymorphic encoder | msfvenom -e x86/shikata_ga_nai | ✅ |
| 46 | XOR encoder | msfvenom -e x86/xor_dynamic | ✅ |
| 47 | call4_dword_xor | msfvenom -e x86/call4_dword_xor | ✅ |
| 48 | Encoder chain (multiple passes) | msfvenom -i N | ✅ |
| 49 | EXE template injection | msfvenom -x cleantemplate.exe | ✅ |
| 50 | AV signature evasion (msfvenom limitations) | manual | 👤 |
| 51 ⭐ | Modern AMSI / EDR bypass (Veil, Shellter) | Veil-Evasion, Shellter | ✅ |
| 52 | Manual creative encoder chain | analyst | 👤 |

---

## §6 — Database Integration

| # | Technique | Command | Auto? |
|---|---|---|---|
| 53 | db_connect to PostgreSQL | db_connect | ✅ |
| 54 | db_nmap (Metasploit-aware scan) | db_nmap | ✅ |
| 55 | hosts / services list | hosts, services | ✅ |
| 56 | vulns query | vulns | ✅ |
| 57 | loot dump | loot | ✅ |
| 58 | creds management | creds | ✅ |

---

## §7 — Meterpreter Operations

| # | Technique | Command | Auto? |
|---|---|---|---|
| 59 | shell drop (cmd) | shell | ✅ |
| 60 | upload / download files | upload, download | ✅ |
| 61 | screenshot | screenshot | ✅ |
| 62 | keylogger | keyscan_start | ✅ |
| 63 | webcam_snap | webcam_snap | ✅ |
| 64 | mic recording | record_mic | ✅ |
| 65 | port forwarding | portfwd add | ✅ |
| 66 | route (pivot) | route add | ✅ |
| 67 | autoroute | post/multi/manage/autoroute | ✅ |
| 68 | SOCKS proxy | auxiliary/server/socks_proxy | ✅ |
| 69 | Manual creative Meterpreter chain | analyst | 👤 |
| 70 | Manual evasion (process migration) | migrate | 👤 |

---

## §8 — Modern AV/EDR Evasion (msfvenom) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 ⭐ | shellcode → C# loader (Donut + msfvenom) | Donut + custom | ✅ |
| 72 ⭐ | Donut + Sliver / Mythic stagers | Donut + Sliver | ✅ |
| 73 ⭐ | Process injection via reflective DLL | manual + custom | ✅ |
| 74 ⭐ | Hells Gate / Halos Gate syscall stubs | custom + research | ✅ |
| 75 ⭐ | AMSI patch in-memory | manual + research | ✅ |
| 76 ⭐ | ETW patch | manual + research | 👤 |
| 77 ⭐ | Sandbox detection bypass | manual + custom | 👤 |
| 78 ⭐ | Manual creative EDR evasion chain | analyst | 👤 |

---

## Compliance Mapping
- **OSCP / OSCE / OSEP methodology** · **MITRE ATT&CK Execution + Lateral Movement**

## VulnusLab Metasploit Status
- Status: 🟡 SOON (per modules_2026_inventory.md #9)
- Planned: 12 reference modules wrapped via msfconsole
- Coverage: ~0% (UI placeholder)

## Roadmap to 100%
1. Phase MSF-1: Wrap msfconsole RPC API (msfrpc-client)
2. Build §1 auxiliary scanners (10)
3. Build §2 exploit catalog (22)
4. Build §3 payload generator UI (10)
5. Build §4 post-ex catalog (12)
6. Build §5 encoder + §6 DB + §7 meterpreter (26)
7. Build §8 modern EDR bypass (8 ⭐)

## References
- Metasploit docs: https://docs.metasploit.com/
- Offensive Security PWK / OSCP: https://www.offsec.com/
- Rapid7 Module Documentation: https://github.com/rapid7/metasploit-framework
- LOLBAS: https://lolbas-project.github.io/
- Donut: https://github.com/TheWover/donut
