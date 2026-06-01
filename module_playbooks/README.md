# VulnusLab Module Playbooks

**31 canonical 100% Full Industry Standard catalogues** — one per module from `modules_2026_inventory.md`.

Files are prefixed with their build-menu number (`01_` to `31_`) so they self-sort by build priority.

When you type a **number** (e.g. `5`) I read the matching playbook and forge the module.

---

## LIVE Modules (audit + upgrade to 100%)
| # | File | Module | Current | Target |
|---|---|---|---|---|
| 1 | [01_recon.md](01_recon.md) | Information Gathering | 96% | 100% (184 tech) |
| 2 | [02_vuln.md](02_vuln.md) | Vulnerability Scanning | 10% | 100% (226 tech) |
| 3 | [03_webapp.md](03_webapp.md) | Web App Pentesting | TBD | 100% (198 tech) |
| 4 | [04_osint.md](04_osint.md) | Advanced OSINT | ~25% | 100% (110 tech) |
| 5 | [05_mobile.md](05_mobile.md) | Mobile Security | 21% | 100% (252 tech) |
| 6 | [06_exploit.md](06_exploit.md) | Exploitation Catalog | ~10% | 100% (100 tech) |
| 7 | [07_bof.md](07_bof.md) | Buffer Overflow | ~30% | 100% (80 tech) |
| 8 | [08_password.md](08_password.md) | Password Attacks | ~1% | 100% (95 tech) |

## SOON Modules (build from playbook)
| # | File | Module | Techniques |
|---|---|---|---|
| 9 | [09_client_side.md](09_client_side.md) | Client-Side Attacks | 75 |
| 10 | [10_system_exploit.md](10_system_exploit.md) | System Exploitation | 80 |
| 11 | [11_metasploit.md](11_metasploit.md) | Metasploit Framework | 70 |
| 12 | [12_privesc.md](12_privesc.md) | Privilege Escalation | 90 |
| 13 | [13_post_exploit.md](13_post_exploit.md) | Post-Exploitation | 75 |
| 14 | [14_pivot.md](14_pivot.md) | Pivoting & Lateral | 60 |
| 15 | [15_tunnel.md](15_tunnel.md) | Port Redirection & Tunneling | 50 |
| 16 | [16_network.md](16_network.md) | Network Attacks | 105 |
| 17 | [17_auth_attacks.md](17_auth_attacks.md) | Authentication Attacks | 75 |
| 18 | [18_wireless.md](18_wireless.md) | Wireless Network Attacks | 90 |
| 19 | [19_ad.md](19_ad.md) | Active Directory Attacks | 130 |
| 20 | [20_av_evasion.md](20_av_evasion.md) | AV / EDR Evasion | 80 |
| 21 | [21_cloud.md](21_cloud.md) | Cloud Security Testing | 165 |
| 22 | [22_apisec.md](22_apisec.md) | API Security Testing | 140 |

## MISSING Modules (NEW for 2026)
| # | File | Module | Priority | Techniques |
|---|---|---|---|---|
| 23 | [23_ai_llm.md](23_ai_llm.md) | AI / LLM Security | P0 | 130 |
| 24 | [24_container_k8s.md](24_container_k8s.md) | Container / Kubernetes | P0 | 142 |
| 25 | [25_supply_chain.md](25_supply_chain.md) | Supply Chain Security | P0 | 110 |
| 26 | [26_phishing.md](26_phishing.md) | Phishing / Social Eng | P1 | 75 |
| 27 | [27_red_team.md](27_red_team.md) | Adversary Emulation | P1 | 90 |
| 28 | [28_hybrid_identity.md](28_hybrid_identity.md) | Entra ID / Azure AD | P1 | 95 |
| 29 | [29_sspm.md](29_sspm.md) | SaaS Security Posture | P2 | 90 |
| 30 | [30_iot_ot.md](30_iot_ot.md) | IoT / OT / ICS | P2 | 90 |
| 31 | [31_firmware.md](31_firmware.md) | Firmware / Embedded | P3 | 75 |

---

## Workflow

```
User types: 23
  ↓
I read module_playbooks/23_ai_llm.md
  ↓
I forge all 130 techniques → tools/ai_llm/* + endpoints + frontend + PDF
  ↓
Result: ai_llm module = 100% Full Industry Standard
```

## Batch Codes
- **B1** = #23 + #24 + #25 (all P0 missing)
- **B2** = #26 + #27 + #28 (all P1 missing)
- **B3** = #29 + #30 + #31 (all P2/P3 missing)
- **BS** = upgrade all 8 LIVE (#1–#8)
- **BO** = build all 14 SOON (#9–#22)

## Grand Total
**31 module playbooks · ~3,725 techniques · 100% Full Industry Standard 2026 coverage.**
