# VulnusLab Module Standardization Spec

Goal: Bring all 23 modules up to the same quality as Web Application Pentesting.
Each module: user input → tools execute → results display → branded PDF report.

## Reference: WebAppPentest component (line ~1700+ in src/App.js)
Pattern to copy: target input → phase selection → run/stop controls → tabs (phases/findings/raw) → PDF download.

## Modules requiring work

| # | Module | Inputs | Tools | PDF |
|---|---|---|---|---|
| 1 | Network Attacks | Target IP, Gateway, Interface | ARP spoof, MITM, DNS spoof | network_*.pdf |
| 2 | System Exploitation | Target URL, LHOST, LPORT | MSFvenom, format strings | sysexploit_*.pdf |
| 3 | Cloud Security | URL, S3 bucket, region | S3 enum, IAM, Docker, K8s | cloud_*.pdf |
| 4 | Authentication Attacks | URL, user, hash, domain | PtH, Kerberos, LDAP, NTLM | auth_*.pdf |
| 5 | Active Directory | DC, domain, creds | BloodHound, kerbrute, responder | ad_*.pdf |
| 6 | Privilege Escalation | Target IP, OS, session | linpeas, winpeas, GTFOBins | privesc_*.pdf |
| 7 | Post Exploitation | Session info | Persistence, harvest | post_*.pdf |
| 8 | Pivoting | Pivot host, subnet | chisel, ligolo, proxychains | pivot_*.pdf |
| 9 | Wireless | Interface, BSSID, channel | aircrack-ng, wifite | wireless_*.pdf |
| 10 | Password Attacks | Hash, wordlist, mode | hashcat, john, hydra | password_*.pdf |
| 11 | Mobile | APK, package | apktool, jadx, frida | mobile_*.pdf |
| 12 | API Security | Base URL, token, OpenAPI | OWASP API Top 10 | api_*.pdf |
| 13 | AV Evasion | Payload, target OS | Veil, msfvenom, shellter | avevasion_*.pdf |
| 14 | Tunneling | Pivot, ports | chisel, ligolo, socat | tunnel_*.pdf |
| 15 | Client-Side | Target URL, payload | BeEF, HTA, office macros | client_*.pdf |
| 16 | Metasploit | RHOST, RPORT, module | msfconsole automation | msf_*.pdf |

## Required UI per module
- Target input + history dropdown
- Optional auth (cookie/bearer)
- Phase selection checkboxes
- Run/Stop/PDF buttons
- Tabbed results (Phases / Findings / Raw)

## PDF requirements per module
- VulnusLab shield logo on cover
- Module-specific title
- Executive Summary severity table
- Tools Used list
- Findings grouped by severity
- End-of-report block: vulnuslab.com · support@vulnuslab.com
- Per-page footer: VulnusLab | CONFIDENTIAL · vulnuslab.com

## Admin vs User separation

**User sees:** all 23 modules in sidebar, OWN scan history, OWN trial/sub status, upgrade button.

**Admin only:** user management panel, all-users scan history, trial extend/plan change/suspend, Tool Manager, Settings, renewal log, system health, Lemon Squeezy events.

Backend: every admin endpoint calls `_admin_only(user)` → HTTP 403 if not ADMIN.
Frontend: admin UI wrapped in `{isSuperAdmin && (...)}`.

## Status tracking

Phase 1: Network + Auth + AD + Privesc
Phase 2: API + Mobile + Cloud + Wireless
Phase 3: Password + Post + Pivoting + AV
Phase 4: Tunneling + Client + System + Metasploit
Phase 5: Admin panel audit + permission enforcement
