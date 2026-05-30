# Client-Side Attacks — Master Reference (`client_side_ruff`)

**100% Full Industry Standard catalogue** — aligned with MITRE ATT&CK Initial Access via User Execution + BeEF canon + modern browser exploit methodology + 2024–2026 industry additions.

7 sections, 75 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Browser Hooks / BeEF | 10 | 8 | 2 |
| 2 | Document / Office Macros | 12 | 10 | 2 |
| 3 | HTML Application (HTA) | 6 | 5 | 1 |
| 4 | LNK / Shortcut Abuse | 8 | 7 | 1 |
| 5 | Browser-side Exploits | 12 | 8 | 4 |
| 6 | Social Engineering Payload Delivery | 14 | 11 | 3 |
| 7 | Modern Browser Surface (Manifest v3, WebView) ⭐ | 10 | 7 | 3 |
| **TOTAL** | | **72** | **56** | **16** |

---

## §1 — Browser Hooks / BeEF

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | BeEF hook delivery via XSS | BeEF | ✅ |
| 2 | BeEF browser-info collection | BeEF | ✅ |
| 3 | BeEF clipboard hijack | BeEF | ✅ |
| 4 | BeEF webcam / mic access prompt | BeEF | ✅ |
| 5 | BeEF tabnabbing | BeEF | ✅ |
| 6 | BeEF browser-pivoted internal scan | BeEF | ✅ |
| 7 | BeEF social-engineering modules | BeEF | ✅ |
| 8 | Custom JS keylogger | custom | ✅ |
| 9 | Manual creative hook chain | analyst | 👤 |
| 10 | Manual session-replay attack | analyst | 👤 |

---

## §2 — Document / Office Macros

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 11 | macro_pack VBA generation | macro_pack | ✅ |
| 12 | VBA → PowerShell stager | manual + custom | ✅ |
| 13 | Excel 4.0 macro abuse | macro_pack -G XLM | ✅ |
| 14 | Word remote template injection | RemoteTemplateInjection | ✅ |
| 15 | DDE field abuse (legacy) | manual + custom | ✅ |
| 16 | OLE object embedding | manual + custom | ✅ |
| 17 | PDF JS embed | OneFile / pdfattach | ✅ |
| 18 ⭐ | OneNote .one file attack chain | custom + macro_pack | ✅ |
| 19 ⭐ | ISO / IMG container delivery | custom + tools | ✅ |
| 20 ⭐ | Microsoft Outlook custom form | manual + custom | ✅ |
| 21 | Manual Office macro evasion | analyst | 👤 |
| 22 | Manual VBA stomping | analyst + EvilClippy | 👤 |

---

## §3 — HTML Application (HTA)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 23 | HTA payload generation | msfvenom -f hta-psh | ✅ |
| 24 | mshta.exe execution via URL | manual + custom | ✅ |
| 25 | HTA in IFrame | custom | ✅ |
| 26 | HTA → PowerShell stager chain | manual + custom | ✅ |
| 27 ⭐ | HTA AMSI bypass | custom + research | ✅ |
| 28 | Manual creative HTA evasion | analyst | 👤 |

---

## §4 — LNK / Shortcut Abuse

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 29 | LNK payload generation | lnk2pwn, manual | ✅ |
| 30 | LNK icon spoofing | manual + custom | ✅ |
| 31 | LNK + PowerShell stager | custom | ✅ |
| 32 | LNK in archive (.zip social eng) | custom | ✅ |
| 33 ⭐ | LNK + .vbs / .js chain (2024+) | custom + research | ✅ |
| 34 ⭐ | Mark-of-the-Web bypass | manual + research | ✅ |
| 35 | URL file (.url) abuse | manual + custom | ✅ |
| 36 | Manual creative LNK chain | analyst | 👤 |

---

## §5 — Browser-side Exploits

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 37 | Chrome 0-day exploit | manual + research | 👤 |
| 38 | Firefox / Edge / Safari CVE | manual + ExploitDB | ✅ |
| 39 | Drive-by download | manual + custom | ✅ |
| 40 | Clickjacking | nuclei + custom | ✅ |
| 41 | Cross-origin info leak | manual + custom | ✅ |
| 42 ⭐ | XS-Leaks (cross-site leaks) | XS-Leaks DB + Burp | ✅ |
| 43 | Browser plugin / extension CVE | nuclei + manual | ✅ |
| 44 | UXSS (universal XSS) | manual + research | 👤 |
| 45 | PDF reader CVE delivery | manual + ExploitDB | ✅ |
| 46 | Manual browser sandbox escape | analyst | 👤 |
| 47 | Manual creative chain (DOM → renderer) | analyst | 👤 |
| 48 | Watering-hole attack design | analyst | 👤 |

---

## §6 — Social Engineering Payload Delivery

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 49 | Phishing email template build | GoPhish, SET | ✅ |
| 50 | Phishing site clone | SET, httrack | ✅ |
| 51 | Reverse-proxy MITM phishing | EvilGinx2 | ✅ |
| 52 | Browser-in-the-Browser (BitB) | custom + HTML | ✅ |
| 53 | URL shortener obfuscation | custom + bit.ly | ✅ |
| 54 | Open redirect abuse (legitimate domain) | manual + recon | ✅ |
| 55 | Punycode IDN homograph | custom + IDN | ✅ |
| 56 | QR code phishing (quishing) | custom + qrcode | ✅ |
| 57 ⭐ | Calendar event attack (.ics injection) | custom | ✅ |
| 58 ⭐ | Slack / Teams / Discord phishing | custom + manual | ✅ |
| 59 ⭐ | Adversary-in-the-Middle (AiTM) MFA bypass | EvilGinx2, Modlishka | ✅ |
| 60 | Manual creative pretext build | analyst | 👤 |
| 61 | Manual psychological hook design | analyst | 👤 |
| 62 | Manual click-rate optimization | analyst | 👤 |

---

## §7 — Modern Browser Surface ⭐ NEW (2024+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 63 ⭐ | Chrome Manifest v3 extension abuse | manual + custom | ✅ |
| 64 ⭐ | Browser extension privilege escalation | manual + custom | ✅ |
| 65 ⭐ | Service Worker persistence | manual + Burp | ✅ |
| 66 ⭐ | Push notification spam abuse | manual + custom | ✅ |
| 67 ⭐ | WebUSB / WebSerial / WebHID prompt abuse | manual + custom | ✅ |
| 68 ⭐ | WebRTC IP leak | webrtcleaks.com + custom | ✅ |
| 69 ⭐ | Cross-Origin-Embedder-Policy bypass | manual + research | ✅ |
| 70 ⭐ | Storage Access API abuse | manual + Burp | 👤 |
| 71 ⭐ | Manual passwordless / Passkey phishing | analyst | 👤 |
| 72 ⭐ | Manual modern browser sandbox escape | analyst | 👤 |

---

## Compliance Mapping
- **MITRE ATT&CK T1204 (User Execution)** · **MITRE ATT&CK T1566 (Phishing)** · **NIST SP 800-115 §4.4**

## VulnusLab Client-Side Status
- Status: 🟡 SOON (per modules_2026_inventory.md #7)
- Planned: BeEF Hook, HTA Payload, Office Macro
- Coverage: ~0%

## Roadmap to 100%
1. Build §1 BeEF + §2 Office macros (~22 scanners)
2. Build §3 HTA + §4 LNK (14)
3. Build §5 browser exploits (12)
4. Build §6 social-eng delivery (14)
5. Build §7 modern browser surface (10 ⭐)

## References
- BeEF: https://beefproject.com/
- macro_pack: https://github.com/sevagas/macro_pack
- EvilGinx2: https://github.com/kgretzky/evilginx2
- SET (Social Engineer Toolkit): https://github.com/trustedsec/social-engineer-toolkit
- GoPhish: https://getgophish.com/
- XS-Leaks DB: https://xsleaks.dev/
