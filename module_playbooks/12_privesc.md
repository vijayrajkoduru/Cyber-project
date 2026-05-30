# Privilege Escalation — Master Reference (`privesc_ruff`)

**100% Full Industry Standard catalogue** — aligned with MITRE ATT&CK TA0004 + GTFOBins + LOLBAS + LinPEAS/WinPEAS canon + 2024–2026 industry additions.

7 sections, 90 techniques. Overlaps with `system_exploit_ruff` and `ad_ruff`; this is the focused enumeration-driven view.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Linux Enumeration | 18 | 17 | 1 |
| 2 | Windows Enumeration | 18 | 17 | 1 |
| 3 | macOS Enumeration | 10 | 8 | 2 |
| 4 | Sudo / SUID / Caps Abuse | 12 | 11 | 1 |
| 5 | Service / Cron / Scheduled Abuse | 10 | 9 | 1 |
| 6 | Kernel CVE Match | 10 | 9 | 1 |
| 7 | Container / Cloud Privesc ⭐ | 10 | 7 | 3 |
| **TOTAL** | | **88** | **78** | **10** |

---

## §1 — Linux Enumeration

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 1 | LinPEAS | LinPEAS | ✅ |
| 2 | LinEnum | LinEnum | ✅ |
| 3 | linux-exploit-suggester (kernel CVE) | linux-exploit-suggester | ✅ |
| 4 | linuxprivchecker | linuxprivchecker | ✅ |
| 5 | linux-smart-enum | linux-smart-enum | ✅ |
| 6 | pspy (no-root process spy) | pspy | ✅ |
| 7 | Hostname / kernel / distro fingerprint | uname + LinPEAS | ✅ |
| 8 | Sudo -l enumeration | sudo -l | ✅ |
| 9 | SUID find / GTFOBins lookup | find + GTFOBins | ✅ |
| 10 | Capabilities (getcap -r /) | getcap | ✅ |
| 11 | Cron jobs (system + user) | cat /etc/crontab, crontab -l | ✅ |
| 12 | Writable PATH / writable scripts | LinPEAS | ✅ |
| 13 | NFS no_root_squash | LinPEAS | ✅ |
| 14 | Docker group membership | id + LinPEAS | ✅ |
| 15 | LXC / LXD group membership | id + LinPEAS | ✅ |
| 16 | snap / flatpak privesc | LinPEAS + manual | ✅ |
| 17 ⭐ | Wildcard injection (tar/find/cp/rsync) | LinPEAS + GTFOBins | ✅ |
| 18 | Manual creative chain | analyst | 👤 |

---

## §2 — Windows Enumeration

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 19 | WinPEAS | WinPEAS | ✅ |
| 20 | PowerUp | PowerUp | ✅ |
| 21 | PrivescCheck | PrivescCheck | ✅ |
| 22 | Watson / Sherlock (kernel CVE) | Watson | ✅ |
| 23 | SeImpersonate + Potato family | JuicyPotato/GodPotato/PrintSpoofer | ✅ |
| 24 | Unquoted service path | PowerUp | ✅ |
| 25 | Writable service binary | PowerUp | ✅ |
| 26 | Writable service registry | PowerUp | ✅ |
| 27 | AlwaysInstallElevated | PowerUp | ✅ |
| 28 | Stored credentials (cmdkey, vault) | PowerUp + vault | ✅ |
| 29 | DLL hijacking opportunities | DLLHijackAuditKit | ✅ |
| 30 | UAC bypass (UACME) | UACME | ✅ |
| 31 | Scheduled task abuse | schtasks + manual | ✅ |
| 32 | AutoRun keys (registry) | autoruns.exe + custom | ✅ |
| 33 | Token impersonation (Incognito) | meterpreter + incognito | ✅ |
| 34 | Service account weak password | PowerUp + custom | ✅ |
| 35 ⭐ | LAPS reading rights | LAPSToolkit | ✅ |
| 36 | Manual creative chain | analyst | 👤 |

---

## §3 — macOS Enumeration

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 37 | macPEAS | macPEAS | ✅ |
| 38 | SUID / SGID enumeration | find / -perm -4000 | ✅ |
| 39 | Launch Agent / Daemon writable | manual + ls | ✅ |
| 40 | Login Item privesc | manual + custom | ✅ |
| 41 | Sudoers misconfig | sudo -l | ✅ |
| 42 | XPC service enumeration | manual + custom | ✅ |
| 43 | TCC bypass (transparency / consent) | manual + research | ✅ |
| 44 | SIP bypass | manual + research | 👤 |
| 45 | Manual creative chain | analyst | 👤 |
| 46 | Manual Apple Silicon-specific | analyst | ✅ |

---

## §4 — Sudo / SUID / Caps Abuse

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 47 | Sudo CVE list (Baron Samedit, etc.) | sudo --version + check | ✅ |
| 48 | Sudo NOPASSWD with GTFOBins entry | sudo -l + GTFOBins | ✅ |
| 49 | Sudo env_keep abuse | sudo -l + custom | ✅ |
| 50 | Sudo LD_PRELOAD abuse | sudo -l + custom | ✅ |
| 51 | Sudo askpass abuse | manual + custom | ✅ |
| 52 | SUID binary in GTFOBins | GTFOBins lookup | ✅ |
| 53 | Custom SUID binary RE | manual + ghidra | ✅ |
| 54 | setcap cap_setuid+ep | getcap + manual | ✅ |
| 55 | cap_dac_read_search abuse | manual + custom | ✅ |
| 56 ⭐ | cap_sys_module insertion | manual + custom | ✅ |
| 57 ⭐ | cap_sys_admin → mount escape | manual + research | ✅ |
| 58 | Manual creative cap chain | analyst | 👤 |

---

## §5 — Service / Cron / Scheduled Abuse

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 59 | Writable cron job | LinPEAS + manual | ✅ |
| 60 | Cron PATH abuse | manual + custom | ✅ |
| 61 | systemd unit writable | LinPEAS + custom | ✅ |
| 62 | systemd unit weak permission | LinPEAS | ✅ |
| 63 | Windows scheduled task writable | PowerUp + custom | ✅ |
| 64 | Windows service binary writable | PowerUp | ✅ |
| 65 | Windows service permission writable | PowerUp | ✅ |
| 66 | Windows AutoRun key writable | PowerUp | ✅ |
| 67 ⭐ | Linux .desktop autostart abuse | manual + custom | ✅ |
| 68 | Manual creative scheduled-task chain | analyst | 👤 |

---

## §6 — Kernel CVE Match

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 69 | linux-exploit-suggester | linux-exploit-suggester | ✅ |
| 70 | Watson (Windows kernel CVE) | Watson | ✅ |
| 71 | Sherlock (Windows) | Sherlock.ps1 | ✅ |
| 72 | wesng (Windows Exploit Suggester) | wesng | ✅ |
| 73 | Kernel version → CVE pivot | uname -r + NVD | ✅ |
| 74 | Module / driver CVE match | lsmod + NVD | ✅ |
| 75 | macOS kernel CVE match | sw_vers + NVD | ✅ |
| 76 ⭐ | nf_tables UAF (CVE-2024-1086) detect | uname + check | ✅ |
| 77 ⭐ | CVE-2024-* Linux pwn check | exploit-suggester | ✅ |
| 78 | Manual creative kernel chain | analyst | 👤 |

---

## §7 — Container / Cloud Privesc ⭐ NEW

| # | Technique | Tool | Auto? |
|---|---|---|---|
| 79 ⭐ | Docker socket mount detect | manual + ls | ✅ |
| 80 ⭐ | Privileged container detect | manual + custom | ✅ |
| 81 ⭐ | Capability-based escape | manual + custom | ✅ |
| 82 ⭐ | Leaky Vessels (runc CVE-2024-21626) | trivy + custom | ✅ |
| 83 ⭐ | Kubernetes RBAC privesc (BloodHound-K8s) | KubeHound | ✅ |
| 84 ⭐ | EKS IRSA / Workload Identity abuse | custom + cloud | ✅ |
| 85 ⭐ | Cloud metadata service (IMDSv1) → IAM | manual + curl | ✅ |
| 86 | Manual creative container escape | analyst | 👤 |
| 87 | Manual cross-cloud privesc | analyst | 👤 |
| 88 | Manual hybrid identity privesc | analyst | 👤 |

---

## Compliance Mapping
- **MITRE ATT&CK TA0004** · **NIST SP 800-53 AC family** · **OSCP / OSEP methodology**

## VulnusLab Privesc Status
- Status: 🟡 SOON (per modules_2026_inventory.md #10)
- Planned: LinPEAS, SUID Binaries, Sudo Analysis, Linux Capabilities, Cron Jobs, Exploit Suggester
- Coverage: ~0%

## Roadmap to 100%
1. Build §1 + §2 + §3 Linux/Win/macOS enum wrappers (46 scanners)
2. Build §4 sudo/SUID/caps (12)
3. Build §5 service/cron (10)
4. Build §6 kernel CVE match (10)
5. Build §7 container/cloud privesc ⭐ (10)

## References
- LinPEAS / WinPEAS: https://github.com/peass-ng/PEASS-ng
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- PowerUp: https://github.com/PowerShellMafia/PowerSploit
- PrivescCheck: https://github.com/itm4n/PrivescCheck
- linux-exploit-suggester: https://github.com/mzet-/linux-exploit-suggester
- wesng: https://github.com/bitsadmin/wesng
