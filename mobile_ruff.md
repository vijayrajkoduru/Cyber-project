# Mobile Pentest — Master Reference (`mobile_ruff`)

Complete catalogue of mobile penetration testing techniques across 11 categories.
Use this as the master knowledge base when forging or improving Mobile module scanners.

**Legend:**
- = Can be automated (passive / 3rd-party / scriptable)
- (probe) = Detection automatable; bypass requires manual setup
- = Manual — requires connected device, jailbreak, or human creativity

---

## Summary

| § | Section | Techniques | Auto | Probe-Auto | Manual |
|---|---|---|---|---|---|
| 1 | APP BINARY (Static) | 16 | 11 | 0 | 5 |
| 2 | RUNTIME / IN-MEMORY | 14 | 0 | 5 | 9 |
| 3 | STORAGE (Data-at-Rest) | 15 | 11 | 0 | 4 |
| 4 | CRYPTO | 9 | 7 | 0 | 2 |
| 5 | NETWORK / TRAFFIC | 17 | 4 | 2 | 11 |
| 6 | IPC / PLATFORM | 14 | 13 | 0 | 1 |
| 7 | WEBVIEW | 7 | 5 | 0 | 2 |
| 8 | AUTH / SESSION | 11 | 6 | 1 | 4 |
| 9 | BACKEND / API | 9 | 8 | 0 | 1 |
| 10 | SUPPLY CHAIN / DIST. | 7 | 6 | 0 | 1 |
| 11 | OS / DEVICE / SOCIAL | 12 | 2 | 0 | 10 |
| **TOTAL** | | **131** | **73** | **8** | **50** |

**56% automatable** (auto + probe) → ~73 techniques are realistic SaaS-scanner candidates.

---

## §1 — APP BINARY (Static Analysis)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | APK decompile (Smali + Java) | apktool, jadx | |
| 2 | IPA unpack + class-dump | unzip, class-dump, otool | |
| 3 | Manifest audit (debuggable, allowBackup, exported) | AAPT, xml parse | |
| 4 | Info.plist audit (ATS, schemes, capabilities) | plistlib | |
| 5 | network_security_config.xml audit | xml parse | |
| 6 | Hardcoded secret extraction (AWS, Firebase, JWT, Stripe) | apkleaks, trufflehog, regex | |
| 7 | Hardcoded URL / endpoint dump | ripgrep | |
| 8 | Smali patching → resign → reinstall | apktool + jarsigner | |
| 9 | Repackaging / trojanizing legit APK | apktool + custom payload | |
| 10 | Resource tampering (strings, assets, layouts) | apktool | |
| 11 | adb backup extraction | `adb backup com.app` | |
| 12 | Native lib hardening check (NX, PIE, RELRO, canary) | checksec, otool | |
| 13 | Mach-O / ELF reverse engineering | Ghidra, Hopper, IDA | |
| 14 | Symbol stripping audit | nm, strings | |
| 15 | Bytecode analysis (malware signatures) | Quark-Engine | |
| 16 | MobSF aggregate scan | MobSF CLI | |

---

## §2 — RUNTIME / IN-MEMORY

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 17 | Frida method hooking | Frida + frida-server | (probe) |
| 18 | Objection workflows (auto-bypass kit) | Objection | (probe) |
| 19 | Cycript runtime manipulation (iOS) | Cycript | |
| 20 | LLDB / GDB live debugging | LLDB, GDB | |
| 21 | Memory dumping (keys, tokens) | Fridump, gcore | |
| 22 | Method swizzling (Obj-C) | Frida, Theos | |
| 23 | Xposed / LSPosed system hooks | LSPosed | |
| 24 | Anti-debug bypass (ptrace, isDebuggerConnected) | Frida patch | (probe) |
| 25 | Root detection bypass (RootBeer, SafetyNet) | Frida, Magisk | (probe) |
| 26 | Jailbreak detection bypass | Liberty Lite, A-Bypass | (probe) |
| 27 | Emulator detection bypass (props, sensors) | MagiskHide | |
| 28 | Play Integrity / Attest bypass | Frida + Magisk modules | |
| 29 | DexClassLoader runtime inspection | Frida | |
| 30 | JNI bridge hooking | Frida + libc interceptor | |

---

## §3 — STORAGE (Data-at-Rest)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 31 | SharedPreferences scraping | adb shell + cat | |
| 32 | SQLite database dump | sqlite3 | |
| 33 | SQLCipher key extraction | grep + Frida | |
| 34 | Realm database dump | Realm Studio | |
| 35 | Core Data inspection (iOS) | sqlite3 | |
| 36 | Android Keystore key extraction | Frida hook KeyStore | |
| 37 | iOS Keychain dump (jailbroken) | keychain-dumper | |
| 38 | Plist scraping (iOS prefs) | plistlib | |
| 39 | App-switcher screenshot leak | FLAG_SECURE check | |
| 40 | WebView cache scraping | adb + grep | |
| 41 | Image / video cache leak | filesystem scan | |
| 42 | Logcat / NSLog token leaks | adb logcat, idevicesyslog | |
| 43 | Clipboard snooping | ClipboardManager audit | |
| 44 | External SD-card readable data | manifest perm check | |
| 45 | Backup extraction (adb / iTunes) | adb backup, iMazing | |

---

## §4 — CRYPTO

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 46 | Weak algo detection (DES, RC4, MD5, SHA1) | ripgrep | |
| 47 | AES/ECB mode flag | smali pattern | |
| 48 | Hardcoded keys / IVs | entropy + regex | |
| 49 | Insecure PRNG (java.util.Random) | smali AST | |
| 50 | Custom crypto detection (XOR loops, homebrew) | pattern match | |
| 51 | TLS version downgrade | network probe | |
| 52 | Certificate validation bypass (TrustManager) | smali grep | |
| 53 | Crypto oracle (padding, timing) | Burp | |
| 54 | Side-channel key recovery (power, EM) | ChipWhisperer | |

---

## §5 — NETWORK / TRAFFIC

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 55 | MITM proxy (Burp / mitmproxy / Caido) | Burp Suite | |
| 56 | SSL pinning bypass — Frida CodeShare | Frida | (probe) |
| 57 | SSL pinning bypass — Objection | Objection | (probe) |
| 58 | SSL pinning bypass — Xposed JustTrustMe | LSPosed | |
| 59 | SSL pinning bypass — SSLKillSwitch2 (iOS) | tweak | |
| 60 | Cleartext HTTP detection | `grep http://` | |
| 61 | ATS / NetworkSecurityConfig audit | plist / xml | |
| 62 | DNS rebinding attack | rebind server | |
| 63 | Rogue Wi-Fi / Evil twin | hostapd + dnsmasq | |
| 64 | Captive portal HTML/JS injection | bettercap | |
| 65 | BLE traffic sniffing | Ubertooth, nRF | |
| 66 | BLE replay / spoofing | gatttool, btlejack | |
| 67 | NFC relay attack | Proxmark3, Flipper Zero | |
| 68 | NFC tag cloning | NFC Tools, Proxmark | |
| 69 | Cellular IMSI catching | Stingray, OpenBTS | |
| 70 | SS7 / Diameter signalling abuse | SigPloit | |
| 71 | Endpoint extraction → backend pivot | regex + dedup | |

---

## §6 — IPC / PLATFORM

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 72 | Exported activity hijack | `am start` + manifest | |
| 73 | Intent redirection | manifest analysis + PoC | |
| 74 | Content provider SQLi | `content://` query | |
| 75 | Content provider path traversal | crafted URI | |
| 76 | Broadcast receiver injection | `am broadcast` | |
| 77 | Sticky broadcast eavesdrop | smali audit | |
| 78 | Deep-link hijack (custom scheme) | competing app | |
| 79 | App-link hijack (assetlinks.json) | DNS / cert audit | |
| 80 | iOS URL scheme abuse | LSApplicationQueriesSchemes | |
| 81 | iOS Universal Link hijack | apple-app-site-association | |
| 82 | Tapjacking / overlay attack | SYSTEM_ALERT_WINDOW | |
| 83 | Pasteboard sniffing (iOS background) | NSPasteboard audit | |
| 84 | XPC service abuse (iOS) | XPC interface enum | |
| 85 | Drozer module enumeration | Drozer | |

---

## §7 — WEBVIEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 86 | addJavascriptInterface RCE | smali grep | |
| 87 | `file://` scheme abuse | setAllowFileAccess check | |
| 88 | WebView XSS | inject + localStorage steal | |
| 89 | Insecure URL loading | shouldOverrideUrlLoading audit | |
| 90 | UXSS via WebView | crafted page | |
| 91 | Mixed content load | WebSettings audit | |
| 92 | WKWebView bridge bypass (iOS) | postMessage abuse | |

---

## §8 — AUTH / SESSION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 93 | Biometric bypass (Frida hook) | Frida | (probe) |
| 94 | JWT none / alg confusion | Burp | |
| 95 | JWT weak HS256 secret crack | hashcat | |
| 96 | OAuth redirect hijack | custom scheme race | |
| 97 | OAuth state/CSRF bypass | proxy intercept | |
| 98 | SMS-OTP interception (READ_SMS perm) | manifest audit | |
| 99 | SIM swap attack | social engineering | |
| 100 | Push token (FCM / APNs) hijack | token extract + replay | |
| 101 | Session fixation across logout | manual test | |
| 102 | Refresh token leakage | log + storage audit | |
| 103 | Account-lockout bypass via device-id rotation | proxy | |

---

## §9 — BACKEND / API (mobile-facing)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 104 | BOLA / IDOR | param swap | (Webapp module) |
| 105 | Mass assignment | JSON tamper | |
| 106 | GraphQL introspection abuse | InQL, graphql-cop | |
| 107 | Rate-limit bypass (device-id rotation) | header rotation | |
| 108 | Replay attack (no nonce) | Burp resend | |
| 109 | Hardcoded admin endpoint discovery | grep decompiled code | |
| 110 | API key reuse across users | account test | |
| 111 | Server-side WebView / SSRF via mobile param | webapp scanner | |
| 112 | Mobile-only header trust (X-Device-ID) | proxy spoof | |

---

## §10 — SUPPLY CHAIN / DISTRIBUTION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 113 | Fake app store sideload | manual | |
| 114 | Malicious SDK detection (ad / tracker / spyware) | Exodus, custom DB | |
| 115 | Dependency confusion | package registry audit | |
| 116 | Update-server hijack | smali + cert audit | |
| 117 | Stalkerware presence check | known-hash DB | |
| 118 | Third-party SDK CVE check | version → NVD lookup | |
| 119 | Compromised signing cert | cert chain verify | |

---

## §11 — OS / DEVICE / SOCIAL

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 120 | Kernel CVE exploit (Dirty COW, etc.) | Metasploit | |
| 121 | Zero-click iMessage / WhatsApp RCE | Pegasus-class | |
| 122 | Bootloader unlock + custom ROM | OEM-specific | |
| 123 | USB juice-jacking | malicious cable | |
| 124 | ADB-over-USB on unlocked device | adb | |
| 125 | Accelerometer keystroke inference | side-channel research | |
| 126 | Screen-recording via Accessibility abuse | a11y service audit | |
| 127 | Smishing (SMS phishing) | social engineering | |
| 128 | Vishing + fake bank app install | social engineering | |
| 129 | Quishing (malicious QR) | social engineering | |
| 130 | Fake MDM profile install (iOS) | configuration profile | |
| 131 | Accessibility-service abuse (Android banking trojans) | manifest audit | |

---

## What's currently in the VulnusLab Mobile module (12 scanners)

| VL Scanner | Maps to # | Auto? | Notes |
|---|---|---|---|
| `google_play_app_enumeration` | (passive, not in list) | | Play Store scrape — pre-binary recon |
| `apple_app_store_enumeration` | (passive, not in list) | | iTunes Search API |
| `app_version_staleness_check` | — | | Pre-binary version timeline |
| `apk_hardcoded_secrets_scan` | #6 | | Implements Tech #6 (passive feed lookup) |
| `github_mobile_secret_leak_scan` | adjacent to #6 | | GitHub Code Search |
| `firebase_open_database_check` | — | | Unauth Firebase URL probe |
| `certificate_transparency_mobile_api_discovery` | adjacent to #71 | | crt.sh mobile-API subdomains |
| `ssl_labs_mobile_api_tls_grade` | #51 partial | | TLS grade via SSL Labs |
| `wayback_machine_mobile_api_endpoint_harvest` | #71 partial | | Historical API endpoints |
| `virustotal_apk_reputation_check` | adjacent to #119 | | AV verdicts on published APK |
| `third_party_sdk_cve_check` | #118 | | NVD CVE for SDKs |
| `shodan_mobile_backend_exposure_check` | adjacent to #71 | | Internet-facing mobile backend |

**Coverage: ~12 of the 73 automatable techniques = ~16% of the auto-able mobile surface.**

---

## Roadmap — Highest-ROI next scanners to add

Prioritized by: (a) automatable, (b) high finding rate on real targets, (c) requires no APK upload (passive only).

### Phase 2 — Passive enrichment (no APK needed)

| Tech # | Scanner name | Why high ROI |
|---|---|---|
| #114 | `exodus_tracker_audit` | Exodus Privacy public API — lists every SDK/tracker in published APKs. Huge GDPR signal. |
| #117 | `stalkerware_presence_check` | Known-hash DB — easy to query, high customer value |
| #119 | `app_signing_cert_audit` | Cert chain verify from store metadata — detects compromised certs |
| #71 | `mobile_api_endpoint_extract` | We have partial; extend with NVD pivot |

### Phase 3 — Customer-uploads-APK flow (Enterprise tier)

| Tech # | Scanner name | Requires |
|---|---|---|
| #1, #3, #6 | `mobsf_static_scan` | Customer uploads APK → MobSF CLI in Docker → static analysis |
| #46-50 | `crypto_weakness_audit` | Same APK upload → ripgrep + AST scan |
| #86-91 | `webview_security_audit` | APK upload → manifest + smali parse |
| #72-83 | `ipc_attack_surface` | APK upload → manifest analysis |

### Phase 4 — Active dynamic (requires device farm)

Deferred until VulnusLab has device-farm integration (BrowserStack / AWS Device Farm / Sauce Labs).

| Tech # | Class | Notes |
|---|---|---|
| #17-30 | Frida-based runtime | Needs connected device |
| #56-59 | SSL pinning bypass | Needs Frida + proxy |
| #93 | Biometric bypass | Needs jailbroken/rooted device |

---

## Reference

- **OWASP Mobile Top 10 (2024):** https://owasp.org/www-project-mobile-top-10/
- **OWASP MASVS:** https://mas.owasp.org/MASVS/
- **OWASP MASTG:** https://mas.owasp.org/MASTG/
- **MobSF:** https://github.com/MobSF/Mobile-Security-Framework-MobSF
- **Frida CodeShare:** https://codeshare.frida.re
- **Objection:** https://github.com/sensepost/objection
- **Exodus Privacy:** https://reports.exodus-privacy.eu.org/en/info/
- **APK Decompilers:** apktool (https://apktool.org), jadx (https://github.com/skylot/jadx)
