# SaaS Security Posture (SSPM) — Master Reference (`sspm_ruff`)

**100% Full Industry Standard catalogue** — aligned with Cloud Security Alliance (CSA) SaaS Security guidelines + AppOmni / Adaptive Shield methodology + 2024–2026 industry additions.

8 sections, 90 techniques. auto · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Microsoft 365 Posture | 16 | 15 | 1 |
| 2 | Google Workspace Posture | 14 | 13 | 1 |
| 3 | Salesforce Posture | 10 | 9 | 1 |
| 4 | Slack / Teams / Discord | 10 | 9 | 1 |
| 5 | Atlassian (Jira / Confluence) | 8 | 7 | 1 |
| 6 | GitHub / GitLab Org Settings | 10 | 9 | 1 |
| 7 | OAuth Connected Apps Inventory | 10 | 8 | 2 |
| 8 | Cross-SaaS Data Flow & DLP | 10 | 7 | 3 |
| **TOTAL** | | **88** | **77** | **11** |

---

## §1 — Microsoft 365 Posture
1 ScubaGear M365 CISA baseline · 2 365 Defender secure-score readout · 3 Conditional Access policy enum · 4 MFA enforcement check · 5 Legacy auth (POP/IMAP/SMTP) disabled · 6 Sign-in risk policy enabled · 7 SharePoint external-sharing audit · 8 OneDrive external-sharing audit · 9 Teams external-meeting audit · 10 Teams external-app audit · 11 Exchange mailbox auto-forward (DLP) · 12 Anonymous link-sharing audit · 13 MFA registration campaign · 14 Self-service password reset audit · 15 Defender for O365 ATP policies · 16 Manual creative M365 audit

## §2 — Google Workspace Posture
17 GWSP (Google Workspace Security Posture) · 18 ScubaGoggles CISA baseline for Google · 19 Admin console role audit · 20 OAuth app marketplace audit · 21 2-Step Verification enforcement · 22 Advanced Protection Program enrollment · 23 Less-secure-app access (legacy) · 24 Drive external-sharing audit · 25 Gmail spoofing protection (SPF/DKIM/DMARC) · 26 Calendar external-sharing audit · 27 Vault retention policy · 28 Context-aware access (zero trust) · 29 User reauthentication frequency · 30 Manual creative GWS audit

## §3 — Salesforce Posture
31 Salesforce Security Health Check API · 32 Profile / Permission Set audit · 33 Apex code static scan · 34 Field-level security audit · 35 Sharing model (org-wide defaults) · 36 IP login restrictions · 37 Session timeout policy · 38 Connected App OAuth scope audit · 39 Lightning Component external-access audit · 40 Manual creative Salesforce audit

## §4 — Slack / Teams / Discord
41 SlackPirate enumeration · 42 Slack OAuth app inventory · 43 Slack DLP keyword scan · 44 Slack channel public/private audit · 45 Slack legacy token / webhook audit · 46 Teams external federation audit · 47 Teams app permission policies · 48 Discord server permission audit · 49 Slack token exfil + abuse · 50 Manual creative Slack/Teams audit

## §5 — Atlassian (Jira / Confluence)
51 Atlassian Access policy audit · 52 Jira / Confluence Cloud OAuth app inventory · 53 Anonymous-access audit (public pages) · 54 Group permission scheme audit · 55 Confluence content scan (secrets in pages) · 56 Atlassian Marketplace add-on audit · 57 External user / guest audit · 58 Manual creative Atlassian audit

## §6 — GitHub / GitLab Org Settings
59 GitHub Org 2FA enforcement · 60 GitHub Org SAML SSO audit · 61 GitHub Action runner audit (self-hosted) · 62 GitHub Action secret leak (workflow logs) · 63 GitHub Personal Access Token (classic vs fine-grained) audit · 64 GitHub App permission audit · 65 GitLab group SSO audit · 66 GitLab CI/CD variables protected audit · 67 GitLab deploy-token audit · 68 Manual creative repo audit

## §7 — OAuth Connected Apps Inventory NEW
69 Tenant-wide OAuth app inventory (M365 + Google) · 70 Risky-scope OAuth app detection · 71 Inactive OAuth app revocation · 72 Multi-tenant app + admin-consent audit · 73 Illicit consent grant detect (T1528) · 74 DUCKTAIL-style consent malware indicators · 75 OAuth scope diff over time · 76 Third-party app data-access scoring · 77 Manual creative app inventory · 78 Manual creative consent revocation

## §8 — Cross-SaaS Data Flow & DLP NEW
79 Cross-SaaS data flow map (M365 → Salesforce → Slack) · 80 Sensitive-data DLP rule audit per SaaS · 81 Outbound file-share audit (Drive/SharePoint → external) · 82 External user inventory (guest counting) · 83 Shadow IT app discovery · 84 CASB-style data classification · 85 SaaS-to-SaaS API integration audit (Zapier, Make, Workato) · 86 Manual creative cross-SaaS chain · 87 Manual creative DLP gap analysis · 88 Manual creative GDPR/DPDP audit

---

## VulnusLab Status
- MISSING (module #29 in inventory) · Priority: P2
- Coverage: 0%

## References
- ScubaGear: https://github.com/cisagov/ScubaGear · ScubaGoggles: https://github.com/cisagov/ScubaGoggles · SkyArk: https://github.com/cyberark/SkyArk · SlackPirate: https://github.com/emtunc/SlackPirate · AppOmni: https://appomni.com/ · Adaptive Shield: https://www.adaptive-shield.com/ · CSA SaaS Security: https://cloudsecurityalliance.org/research/topics/saas
