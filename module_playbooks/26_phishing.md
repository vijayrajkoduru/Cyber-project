# Phishing & Social Engineering — Master Reference (`phishing_ruff`)

**100% Full Industry Standard catalogue** — aligned with MITRE ATT&CK Initial Access T1566 + SET (Social-Engineer Toolkit) canon + 2024–2026 industry additions (AiTM, AI-generated content, deepfakes).

7 sections, 75 techniques. ✅ auto · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Email Phishing (Mass + Spear) | 14 | 11 | 3 |
| 2 | Website Cloning / Credential Harvest | 8 | 7 | 1 |
| 3 | Adversary-in-the-Middle (AiTM) ⭐ | 10 | 8 | 2 |
| 4 | Smishing / Vishing / Quishing | 10 | 5 | 5 |
| 5 | OAuth / App Consent Phishing | 8 | 6 | 2 |
| 6 | Deepfake / AI-generated Content ⭐ | 10 | 4 | 6 |
| 7 | Campaign Management & Reporting | 10 | 10 | 0 |
| **TOTAL** | | **70** | **51** | **19** |

---

## §1 — Email Phishing (Mass + Spear)
1 GoPhish campaign setup · 2 SET (Social-Engineer Toolkit) · 3 King Phisher · 4 Phishery (Office basic-auth harvest) · 5 Mailspoof / spoofcheck (sender check) · 6 SPF / DKIM / DMARC bypass · 7 Email template library (HTML) · 8 ⭐ AI-generated content (LLM) for personalization · 9 ⭐ Spear-phishing OSINT integration (LinkedIn) · 10 Attachment-based delivery (Office macro / HTA / LNK) · 11 ⭐ Calendar invite (.ics) phishing · 12 Manual creative pretext design 👤 · 13 Manual victim psychology profiling 👤 · 14 Manual A/B testing 👤

## §2 — Website Cloning / Credential Harvest
15 SET site cloner · 16 httrack site mirror · 17 GoPhish landing page · 18 Custom React/HTML page with collector backend · 19 IDN homograph (Punycode) lookalike domain · 20 Typo-squat domain registration · 21 Open-redirect abuse · 22 Manual landing-page UX tuning 👤

## §3 — Adversary-in-the-Middle (AiTM) ⭐ NEW
23 ⭐ EvilGinx2 reverse-proxy phishing (with Phishlets) · 24 ⭐ Modlishka · 25 ⭐ Muraena · 26 ⭐ Browser-in-the-Browser (BitB) iframe · 27 ⭐ Custom AiTM with mitmproxy · 28 ⭐ Session-cookie steal + replay · 29 ⭐ MFA bypass via AiTM session capture · 30 ⭐ Conditional Access bypass via stolen session · 31 Manual AiTM Phishlet customization 👤 · 32 Manual creative AiTM chain 👤

## §4 — Smishing / Vishing / Quishing
33 SMS phishing (smishing) — bulk sender · 34 Twilio / Plivo / Bandwidth as SMS gateway · 35 Smishing template library · 36 Vishing call setup (VoIP + spoofed CLI) · 37 ⭐ AI voice-cloning vishing (ElevenLabs, etc.) 👤 · 38 IVR / phone-tree social engineering 👤 · 39 Quishing (QR code phishing) — qrcode + redirect · 40 Quishing in printed materials (poster, sticker) 👤 · 41 Manual vishing pretext / persona 👤 · 42 Manual creative phone chain 👤

## §5 — OAuth / App Consent Phishing
43 ⭐ Microsoft 365 OAuth app consent phishing · 44 ⭐ Google Workspace OAuth consent abuse · 45 ⭐ Custom OAuth client_id phishing · 46 ⭐ Refresh-token abuse post-consent · 47 ⭐ Device code phishing (Microsoft) · 48 ⭐ Illicit consent grant (MITRE T1528) · 49 Manual OAuth app design 👤 · 50 Manual creative consent chain 👤

## §6 — Deepfake / AI-generated Content ⭐ NEW
51 ⭐ AI voice clone (ElevenLabs, Resemble) 👤 · 52 ⭐ AI face-swap video (DeepFaceLab) 👤 · 53 ⭐ AI-written spear phish (GPT-4o, Claude) · 54 ⭐ Deepfake CEO fraud (BEC class) 👤 · 55 ⭐ GoldPickaxe-class face data theft via TestFlight 👤 · 56 ⭐ AI-generated phishing landing page (LLM HTML) · 57 ⭐ Auto-translated multilingual phish · 58 ⭐ AI-generated social profile (sock-puppet) · 59 ⭐ Manual deepfake quality refinement 👤 · 60 ⭐ Manual creative AI-augmented social-eng 👤

## §7 — Campaign Management & Reporting
61 GoPhish tracking pixels (open rate) · 62 GoPhish click rate · 63 Credential capture rate (per phish) · 64 Time-on-page tracking · 65 Multi-stage campaign orchestration · 66 Report metrics export (CSV/JSON) · 67 PDF executive report · 68 MITRE ATT&CK technique mapping per finding · 69 Compliance evidence collection · 70 GDPR / DPDP consent + retention compliance

---

## VulnusLab Status
- 🔴 MISSING (module #26 in inventory) · Priority: 🟡 P1
- Coverage: 0%

## Roadmap to 100%
1. Build §1 GoPhish + SET wrapper (~14 scanners)
2. Build §2 site cloner (8)
3. Build §3 AiTM ⭐ (10 — EvilGinx integration)
4. Build §4 smishing + vishing (10)
5. Build §5 OAuth consent phishing (8 ⭐)
6. Build §6 deepfake / AI content (10 ⭐)
7. Build §7 campaign management UI (10)

## References
- GoPhish: https://getgophish.com/ · SET: https://github.com/trustedsec/social-engineer-toolkit · EvilGinx2: https://github.com/kgretzky/evilginx2 · Modlishka: https://github.com/drk1wi/Modlishka · King Phisher: https://github.com/rsmusllp/king-phisher · MITRE ATT&CK T1566: https://attack.mitre.org/techniques/T1566/
