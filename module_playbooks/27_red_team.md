# Adversary Emulation / Red Team — Master Reference (`red_team_ruff`)

**100% Full Industry Standard catalogue** — aligned with MITRE ATT&CK Enterprise + MITRE Caldera + Atomic Red Team + TIBER-EU / CBEST methodology + 2024–2026 industry additions.

8 sections, 90 techniques. ✅ auto · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Adversary Emulation Plans | 10 | 8 | 2 |
| 2 | Atomic Red Team Tests | 14 | 14 | 0 |
| 3 | MITRE Caldera Operations | 10 | 9 | 1 |
| 4 | C2 Frameworks | 14 | 11 | 3 |
| 5 | Initial Access Simulation | 10 | 8 | 2 |
| 6 | Detection Engineering Validation | 10 | 8 | 2 |
| 7 | Purple Teaming Workflow | 8 | 6 | 2 |
| 8 | Threat Actor TTP Emulation ⭐ | 12 | 9 | 3 |
| **TOTAL** | | **88** | **73** | **15** |

---

## §1 — Adversary Emulation Plans
1 MITRE ATT&CK Navigator coverage · 2 MITRE Adversary Emulation Library (APT29, FIN6, etc.) · 3 Custom emulation plan builder · 4 Scenario-based engagement design · 5 Engagement scope + ROE document · 6 Red Team Operating Procedure · 7 Pre-engagement threat modeling · 8 Post-engagement reporting template · 9 Manual creative scenario design 👤 · 10 Manual threat-actor selection 👤

## §2 — Atomic Red Team Tests
11 invoke-atomicredteam (Windows) · 12 Atomic Red Team Linux · 13 macOS atomic tests · 14 Per-technique YAML automation · 15 T1059 Command Interpreter · 16 T1055 Process Injection · 17 T1003 OS Credential Dumping · 18 T1078 Valid Accounts · 19 T1547 Boot/Logon Autostart · 20 T1110 Brute Force · 21 T1190 Exploit Public-Facing App · 22 T1566 Phishing · 23 T1486 Data Encrypted for Impact (ransomware sim) · 24 Custom atomic-test runner

## §3 — MITRE Caldera Operations
25 Caldera server setup · 26 Caldera agent deployment (Sandcat, Manx, Ragdoll) · 27 Caldera operation autonomous · 28 Caldera operation manual (guided) · 29 Caldera planner (chaining abilities) · 30 Caldera adversary profiles · 31 Caldera abilities library audit · 32 Custom ability YAML authoring · 33 Caldera + Atomic integration · 34 Manual emulation refinement 👤

## §4 — C2 Frameworks
35 Cobalt Strike (commercial, industry std) · 36 ⭐ Sliver (open-source, fastest growing) · 37 ⭐ Havoc framework · 38 ⭐ Mythic (modular Python C2) · 39 ⭐ Brute Ratel C4 (premium EDR-evading) · 40 Empire / Starkiller (PowerShell C2) · 41 Metasploit (legacy, still used) · 42 Merlin (Go, HTTP/2 + HTTP/3) · 43 ⭐ Manual C2 channel design 👤 · 44 ⭐ Custom Malleable C2 profile · 45 ⭐ Manual Domain Fronting (CDN abuse) · 46 ⭐ Manual creative C2 chain 👤 · 47 ⭐ Multi-stage agent (Donut + Sliver) · 48 Manual EDR-aware C2 selection 👤

## §5 — Initial Access Simulation
49 Phishing campaign (GoPhish + AiTM) · 50 Macro / HTA / LNK delivery · 51 Watering-hole attack design · 52 Trusted-vendor compromise simulation · 53 Supply-chain compromise sim · 54 Hardware drop (USB / cable) · 55 Drive-by download · 56 ⭐ Cloud-account compromise sim · 57 Manual creative initial access 👤 · 58 Manual creative pretext build 👤

## §6 — Detection Engineering Validation
59 Sigma rule coverage · 60 Splunk SPL detection · 61 Microsoft Sentinel KQL detection · 62 CrowdStrike Falcon detection coverage · 63 SentinelOne STAR rule · 64 Elastic SIEM detection · 65 YARA rule coverage · 66 Detection-as-code (Panther, Anvilogic) · 67 Manual detection gap analysis 👤 · 68 Manual creative evasion → detection improvement 👤

## §7 — Purple Teaming Workflow
69 Joint red-blue exercise design · 70 SIEM event correlation review · 71 EDR alert tuning · 72 Detection coverage heat-map (ATT&CK Navigator) · 73 Mean-time-to-detect (MTTD) measurement · 74 Mean-time-to-respond (MTTR) measurement · 75 Manual lessons-learned 👤 · 76 Manual remediation roadmap 👤

## §8 — Threat Actor TTP Emulation ⭐ NEW
77 ⭐ APT28 (Fancy Bear) emulation · 78 ⭐ APT29 (Cozy Bear) emulation · 79 ⭐ Lazarus Group emulation · 80 ⭐ FIN7 / FIN8 emulation · 81 ⭐ Conti / LockBit ransomware emulation · 82 ⭐ Volt Typhoon / Chinese APT emulation · 83 ⭐ Cl0p / BlackCat emulation · 84 ⭐ Akira ransomware emulation · 85 ⭐ Scattered Spider (UNC3944) emulation · 86 ⭐ Manual custom-actor profile build 👤 · 87 ⭐ Manual creative threat-intel-driven emulation 👤 · 88 ⭐ Manual TIBER-EU / CBEST engagement 👤

---

## Compliance Mapping
- **MITRE ATT&CK Enterprise** · **TIBER-EU (financial sector regulated red team)** · **CBEST (UK)** · **iCAST / AASE / GBEST**

## VulnusLab Status
- 🔴 MISSING (module #27 in inventory) · Priority: 🟡 P1
- Coverage: 0%

## Roadmap
Build §1–§3 emulation plans + Atomic + Caldera (~34 scanners) → §4 C2 framework integration (14) → §5–§7 (~28) → §8 threat-actor emulation ⭐ (12)

## References
- MITRE Caldera: https://github.com/mitre/caldera · Atomic Red Team: https://atomicredteam.io/ · MITRE ATT&CK: https://attack.mitre.org/ · MITRE Adversary Emulation Library: https://github.com/center-for-threat-informed-defense/adversary_emulation_library · Sliver: https://github.com/BishopFox/sliver · Havoc: https://havocframework.com/ · Mythic: https://github.com/its-a-feature/Mythic · TIBER-EU: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/
