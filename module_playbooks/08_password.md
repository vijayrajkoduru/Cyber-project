# Password Attacks — Master Reference (`password_ruff`)

**100% Full Industry Standard catalogue** — aligned with PTES + OWASP ASVS + NIST SP 800-63B + hashcat / john methodology + 2024–2026 industry additions.

8 sections, 95 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Online Password Attacks | 14 | 13 | 1 |
| 2 | Offline Hash Cracking | 16 | 15 | 1 |
| 3 | Credential Stuffing & Spray | 10 | 9 | 1 |
| 4 | Hash Identification | 8 | 8 | 0 |
| 5 | Password Wordlist & Rule Gen | 12 | 10 | 2 |
| 6 | Cloud Distributed Cracking ⭐ | 8 | 7 | 1 |
| 7 | OS-specific Password Extraction | 12 | 11 | 1 |
| 8 | Modern Auth Bypass (Passkey / MFA) ⭐ | 10 | 6 | 4 |
| **TOTAL** | | **90** | **79** | **11** |

---

## §1 — Online Password Attacks

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | SSH brute force | hydra, medusa | ✅ |
| 2 | FTP brute force | hydra, medusa | ✅ |
| 3 | Telnet brute force | hydra | ✅ |
| 4 | SMB brute force | crackmapexec, hydra | ✅ |
| 5 | RDP brute force | crowbar, hydra | ✅ |
| 6 | HTTP form brute (basic auth + form) | hydra http-form, ffuf | ✅ |
| 7 | MySQL / Postgres / MSSQL brute | hydra | ✅ |
| 8 | LDAP bind brute | hydra | ✅ |
| 9 | IMAP / POP3 / SMTP brute | hydra | ✅ |
| 10 | Kerberos pre-auth brute | kerbrute | ✅ |
| 11 | VNC brute force | hydra | ✅ |
| 12 ⭐ | OAuth2 token endpoint brute | custom + Burp | ✅ |
| 13 | API key enum + brute | custom + Burp | ✅ |
| 14 | Manual creative login attack | analyst | 👤 |

---

## §2 — Offline Hash Cracking

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | hashcat (universal) | hashcat | ✅ |
| 16 | john the ripper | john | ✅ |
| 17 | NTLM (mode 1000) | hashcat | ✅ |
| 18 | NetNTLMv2 (mode 5600) | hashcat | ✅ |
| 19 | Kerberos TGS (Kerberoast mode 13100) | hashcat | ✅ |
| 20 | Kerberos AS-REP (mode 18200) | hashcat | ✅ |
| 21 | bcrypt (mode 3200) | hashcat | ✅ |
| 22 | scrypt (mode 8900) | hashcat | ✅ |
| 23 | Argon2 (mode 14000+) | hashcat | ✅ |
| 24 | MD5 / SHA1 / SHA256 (modes 0/100/1400) | hashcat | ✅ |
| 25 | PBKDF2 (mode 12000+) | hashcat | ✅ |
| 26 | JWT HS256 secret crack (mode 16500) | hashcat | ✅ |
| 27 | ZIP / RAR / 7z password crack | john + custom | ✅ |
| 28 | KeePass / LastPass / 1Password | hashcat / john | ✅ |
| 29 ⭐ | macOS Login Keychain crack | hashcat | ✅ |
| 30 | Manual exotic hash crack | analyst | 👤 |

---

## §3 — Credential Stuffing & Spray

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 31 | Password spray (one pwd × many users) | crackmapexec, kerbrute | ✅ |
| 32 | Credential stuffing (combo list) | OpenBullet, Sentry MBA | ✅ |
| 33 | Credential reuse across services | custom + HIBP | ✅ |
| 34 | Slow-and-low brute (lockout evasion) | custom + delay | ✅ |
| 35 ⭐ | Distributed brute (residential proxies) | custom + proxy | ✅ |
| 36 ⭐ | Token-based stuffing (refresh token reuse) | custom + Burp | ✅ |
| 37 | Stolen credential reuse (HIBP / stealer log) | HIBP + Hudson Rock | ✅ |
| 38 | Manual creative combo list gen | analyst | 👤 |
| 39 ⭐ | Account-lockout bypass via device-id rotation | custom + Burp | ✅ |
| 40 | Cred stuffing rate-limit bypass | header rotation | ✅ |

---

## §4 — Hash Identification

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 41 | hashid identification | hashid | ✅ |
| 42 | name-that-hash (modern) | nth | ✅ |
| 43 | hash-identifier | hash-identifier | ✅ |
| 44 | Format-specific magic byte detect | custom | ✅ |
| 45 | Custom hash format reverse | manual + custom | ✅ |
| 46 | Crackstation online lookup | crackstation API | ✅ |
| 47 | hashes.com lookup | hashes.com API | ✅ |
| 48 ⭐ | Modern hash format detection (mode 22000 WPA) | hashcat | ✅ |

---

## §5 — Password Wordlist & Rule Gen

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 49 | rockyou.txt + SecLists | SecLists | ✅ |
| 50 | crunch wordlist gen | crunch | ✅ |
| 51 | cewl scrape from URL | cewl | ✅ |
| 52 | hashcat rule files (best64, OneRuleToRuleThemAll) | hashcat -r | ✅ |
| 53 | john --rules:Jumbo | john | ✅ |
| 54 | Markov chain (statsprocessor) | hashcat -a 7 | ✅ |
| 55 | PRINCE attack | princeprocessor | ✅ |
| 56 | Mask attack | hashcat -a 3 | ✅ |
| 57 | Combinator attack | hashcat -a 1 | ✅ |
| 58 ⭐ | AI-curated wordlist (LLM-generated) | GPT + custom | ✅ |
| 59 ⭐ | Pwned Passwords k-anonymity lookup | HIBP API | ✅ |
| 60 | Manual creative wordlist build | analyst | 👤 |

---

## §6 — Cloud Distributed Cracking ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 61 ⭐ | Hashtopolis distributed cracking | Hashtopolis | ✅ |
| 62 ⭐ | vast.ai / RunPod GPU rental | manual + scripts | ✅ |
| 63 ⭐ | AWS EC2 spot instance crack | aws + hashcat | ✅ |
| 64 ⭐ | NPK (Naive Password Kracker, AWS-native) | NPK | ✅ |
| 65 ⭐ | RTX 4090 / 5090 single-GPU rig benchmark | hashcat -b | ✅ |
| 66 ⭐ | Cross-cloud crack-as-a-service | custom | ✅ |
| 67 ⭐ | hashcat in K8s (GPU pods) | custom + k8s | ✅ |
| 68 | Manual cost-vs-time optimization | analyst | 👤 |

---

## §7 — OS-specific Password Extraction

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 69 | Windows SAM/SYSTEM hive dump | secretsdump.py | ✅ |
| 70 | LSASS memory dump (Mimikatz) | mimikatz sekurlsa | ✅ |
| 71 | NTDS.dit AD database dump | secretsdump -ntds | ✅ |
| 72 | DPAPI master key + credential extract | mimikatz dpapi | ✅ |
| 73 | Windows credential manager | Mimikatz, custom | ✅ |
| 74 | Linux /etc/shadow extraction (post-root) | manual + cat | ✅ |
| 75 | macOS Keychain dump (root) | security + manual | ✅ |
| 76 | Chrome / Firefox / Edge saved passwords | LaZagne, custom | ✅ |
| 77 | KeePass / LastPass / Bitwarden vault extract | LaZagne | ✅ |
| 78 | Browser session token theft | LaZagne, custom | ✅ |
| 79 ⭐ | NanoDump stealth LSASS (EDR-evading) | NanoDump | ✅ |
| 80 | Manual creative cred-theft chain | analyst | 👤 |

---

## §8 — Modern Auth Bypass (Passkey / MFA) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 81 ⭐ | MFA fatigue / push bombing | manual + custom | 👤 |
| 82 ⭐ | OTP brute (rate-limit bypass) | custom + Burp | ✅ |
| 83 ⭐ | TOTP secret extraction (if stored) | custom + parse | ✅ |
| 84 ⭐ | SIM swap (social engineering) | manual | 👤 |
| 85 ⭐ | Push token (FCM / APNs) hijack | custom + manual | 👤 |
| 86 ⭐ | WebAuthn / Passkey enumeration | custom + Burp | ✅ |
| 87 ⭐ | Passkey downgrade attack | manual + Burp | 👤 |
| 88 ⭐ | EvilGinx2 phishing toolkit (MFA bypass) | EvilGinx2 | ✅ |
| 89 ⭐ | Modlishka phishing | Modlishka | ✅ |
| 90 ⭐ | Browser-in-the-browser (BitB) phishing | custom + Burp | ✅ |

---

## Compliance Mapping
- **NIST SP 800-63B (Authentication)** · **OWASP ASVS V2** · **PCI DSS 4.0 §8** · **MITRE ATT&CK Credential Access (TA0006)**

## VulnusLab Password Status
- Status: ✅ LIVE (hydra only, per memory)
- Estimated coverage: ~1% (massive expansion needed)

## Roadmap to 100%
1. Phase P-1: §1 online brute pack (14 scanners — wrap hydra/medusa/crackmapexec)
2. Phase P-2: §2 offline crack pack (16 — wrap hashcat/john)
3. Phase P-3: §3 stuffing + spray (10)
4. Phase P-4: §4 hash ID + §5 wordlist gen (20)
5. Phase P-5: §6 cloud distributed cracking (8 ⭐)
6. Phase P-6: §7 OS-specific extraction (12)
7. Phase P-7: §8 modern MFA bypass (10 ⭐)

## References
- hashcat: https://hashcat.net/
- john the ripper: https://www.openwall.com/john/
- SecLists: https://github.com/danielmiessler/SecLists
- HIBP Pwned Passwords: https://haveibeenpwned.com/Passwords
- Hashtopolis: https://github.com/hashtopolis/server
- LaZagne: https://github.com/AlessandroZ/LaZagne
- EvilGinx2: https://github.com/kgretzky/evilginx2
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
