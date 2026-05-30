# Hybrid Identity Security (Entra ID / Azure AD) — Master Reference (`hybrid_identity_ruff`)

**100% Full Industry Standard catalogue** — aligned with Microsoft Identity Security canon + ROADtools + AADInternals + SpecterOps Azure research + 2024–2026 industry additions (Entra ID, cross-tenant trust, hybrid AD bridges).

8 sections, 95 techniques. ✅ auto · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Entra ID Recon / Enumeration | 14 | 13 | 1 |
| 2 | Hybrid AD Connect Attacks | 12 | 10 | 2 |
| 3 | Conditional Access Bypass | 10 | 7 | 3 |
| 4 | Token Theft / Replay | 10 | 8 | 2 |
| 5 | Service Principal / App Registration Abuse | 12 | 11 | 1 |
| 6 | Cross-Tenant Attacks | 10 | 7 | 3 |
| 7 | Microsoft 365 Privesc | 12 | 10 | 2 |
| 8 | Modern Entra ID CVE / TTPs ⭐ | 10 | 8 | 2 |
| **TOTAL** | | **90** | **74** | **16** |

---

## §1 — Entra ID Recon / Enumeration
1 ROADrecon (ROADtools) full dump · 2 AADInternals enumeration · 3 azurehound BloodHound-Azure ingest · 4 StormSpotter graph traversal · 5 MSOLSpray password spray · 6 MFASweep MFA enum · 7 o365creeper user enum · 8 AADInternals.org email enum · 9 SkyArk Azure shadow admin · 10 Manual Entra ID PowerShell (AzureAD module) · 11 Manual Graph API exploration 👤 · 12 ⭐ Open ID configuration enum (.well-known) · 13 ⭐ Tenant ID + tenant name leak via DNS · 14 ⭐ ScubaGear M365 baseline (defender-side)

## §2 — Hybrid AD Connect Attacks
15 ADSync server compromise → DA · 16 MSOL_xxxxx service account abuse · 17 ⭐ Seamless SSO Silver Ticket (MSAPPS17) · 18 PHS (Password Hash Sync) extraction · 19 PTA (Pass-Through Auth) agent abuse · 20 ADFS Golden Ticket (cert theft + forge) · 21 AAD Connect Sync API abuse · 22 Manual hybrid bridge audit 👤 · 23 ⭐ Cloud Sync vs AAD Connect differences · 24 ⭐ Permanent Hybrid Admin role abuse · 25 ⭐ Manual cross-tenant AD Connect chain 👤 · 26 ADFS proxy server attack surface

## §3 — Conditional Access Bypass
27 Device-compliance bypass (Intune evasion) · 28 ⭐ Token theft + replay from approved device · 29 Legacy auth (POP/IMAP/SMTP) bypass · 30 Continuous Access Evaluation (CAE) audit · 31 Risk-based policy bypass · 32 Named-locations bypass (VPN egress) · 33 Manual creative CA bypass chain 👤 · 34 Manual policy-gap analysis 👤 · 35 Manual phishing → MFA fatigue chain 👤 · 36 ⭐ Conditional Access policy enumeration (read-only abuse)

## §4 — Token Theft / Replay
37 PRT (Primary Refresh Token) theft (Mimikatz) · 38 ⭐ TokenTactics / TokenTactics V2 · 39 Browser cookie theft → Microsoft session replay · 40 Office desktop client token theft (.aad.* files) · 41 Teams / OneDrive client token theft · 42 ⭐ EvilGinx2 with M365 Phishlet · 43 ⭐ AiTM cookie replay through ROPC flow · 44 Refresh token long-lived abuse · 45 Manual creative token chain 👤 · 46 Manual cookie validity engineering 👤

## §5 — Service Principal / App Registration Abuse
47 Application permission audit (Graph) · 48 Application secret leak (gitleaks) · 49 ⭐ Application certificate theft + use · 50 Owner role abuse (add credentials) · 51 Add user to enterprise app role · 52 ⭐ Service principal vs Application object confusion · 53 ⭐ Delegated permissions vs Application permissions abuse · 54 ⭐ Group-claims abuse · 55 ⭐ Federated identity credentials (workload identity) · 56 ⭐ App Roles claim tampering · 57 Manual service principal pivot 👤 · 58 ⭐ ROADrecon service principal mapping

## §6 — Cross-Tenant Attacks
59 ⭐ Cross-tenant guest user abuse · 60 ⭐ B2B Direct Connect audit · 61 ⭐ Cross-Tenant Synchronization audit · 62 ⭐ Multi-tenant app + admin consent abuse · 63 ⭐ Cross-tenant Conditional Access skew · 64 Manual creative cross-tenant chain 👤 · 65 ⭐ Cross-tenant Entra ID Connect bridge · 66 ⭐ Cross-cloud OIDC trust map (AWS/GCP) · 67 Manual cross-tenant guest enumeration 👤 · 68 Manual cross-tenant privesc 👤

## §7 — Microsoft 365 Privesc
69 Global Admin role enumeration · 70 ⭐ Privileged Identity Management (PIM) abuse · 71 ⭐ Eligible role activation race · 72 SharePoint admin → tenant compromise · 73 Exchange admin → mailbox-of-anyone read · 74 ⭐ Teams admin → bot impersonation · 75 ⭐ Defender admin → audit disable · 76 ⭐ Compliance admin → DLP bypass · 77 ⭐ Outlook custom rules + exfil · 78 ⭐ Manual creative M365 chain 👤 · 79 Manual M365 admin role analysis 👤 · 80 Manual mailbox-of-CEO chain 👤

## §8 — Modern Entra ID CVE / TTPs ⭐ NEW
81 ⭐ MSAPPS17 Seamless SSO Silver Ticket (CVE class) · 82 ⭐ nOAuth (CVE-2023-?) · 83 ⭐ DUCKTAIL malware-style consent abuse · 84 ⭐ Storm-0558 token-forging class · 85 ⭐ Volt Typhoon / Midnight Blizzard TTPs · 86 ⭐ Solorigate-style SAML token theft · 87 ⭐ Manual modern threat-actor emulation 👤 · 88 ⭐ Manual Microsoft IR-report TTP replication 👤 · 89 ⭐ Defender for Identity bypass · 90 ⭐ Sentinel UEBA evasion

---

## Compliance Mapping
- **Microsoft Identity Secure Score** · **CIS Microsoft 365 Foundations Benchmark** · **PCI DSS 4.0 §8** · **HIPAA** · **SOC 2 CC6**

## VulnusLab Status
- 🔴 MISSING (module #28 in inventory) · Priority: 🟡 P1
- Coverage: 0%

## Roadmap
Build §1 recon (14 — ROADtools/azurehound wrappers) → §2 hybrid AD Connect (12) → §3 CA bypass (10) → §4 token theft (10) → §5 service principal (12) → §6 cross-tenant (10) → §7 M365 privesc (12) → §8 modern CVE/TTP (10 ⭐)

## References
- ROADtools: https://github.com/dirkjanm/ROADtools · AADInternals: https://github.com/Gerenios/AADInternals · azurehound: https://github.com/SpecterOps/AzureHound · StormSpotter: https://github.com/Azure/Stormspotter · TokenTactics V2: https://github.com/f-bader/TokenTacticsV2 · MSOLSpray: https://github.com/dafthack/MSOLSpray · MFASweep: https://github.com/dafthack/MFASweep · SkyArk: https://github.com/cyberark/SkyArk · dirkjanm research: https://dirkjanm.io/
