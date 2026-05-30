# Mobile Pentest — Master Reference (`mobile_ruff` v2)

**100% Full Industry Standard catalogue** — aligned with OWASP MASVS v2 + MASTG + OWASP Mobile Top 10 (2024) + OWASP API Top 10 (2023) + PCI MASS + Apple Privacy Manifest + Google CASA/ADA + NIST SP 800-163 Rev 1.

15 sections, 252 techniques. Use this as the master knowledge base when forging or improving Mobile module scanners.

**Legend:**
- ✅ = Can be automated (passive / 3rd-party / scriptable)
- ✅ (probe) = Detection automatable; bypass requires manual setup
- 👤 = Manual — requires connected device, jailbreak, or human creativity
- ⭐ = NEW vs v1 (2024–2026 industry additions)

---

## Summary

| § | Section | Techniques | Auto ✅ | Probe-Auto | Manual 👤 |
|---|---|---|---|---|---|
| 1 | APP BINARY (Static) | 20 | 14 | 0 | 6 |
| 2 | RESILIENCE (Static detection) | 14 | 14 | 0 | 0 |
| 2b | RUNTIME (Phase 4 deferred) | 14 | 0 | 5 | 9 |
| 3 | STORAGE (Data-at-Rest) | 20 | 16 | 0 | 4 |
| 4 | CRYPTO | 12 | 10 | 0 | 2 |
| 5 | NETWORK / TRAFFIC | 25 | 12 | 3 | 10 |
| 6 | IPC / PLATFORM | 26 | 24 | 0 | 2 |
| 7 | WEBVIEW | 14 | 11 | 0 | 3 |
| 8 | AUTH / SESSION | 21 | 12 | 1 | 8 |
| 9 | BACKEND / API (OWASP API 2023) | 22 | 19 | 0 | 3 |
| 10 | SUPPLY CHAIN / DIST | 16 | 14 | 0 | 2 |
| 11 | OS / DEVICE / HARDWARE | 12 | 4 | 0 | 8 |
| 12 | SOCIAL ENGINEERING | 10 | 1 | 1 | 8 |
| 13 | PRIVACY (MASVS-PRIVACY) ⭐ | 12 | 11 | 0 | 1 |
| 14 | PAYMENT / IAP ⭐ | 8 | 6 | 0 | 2 |
| 15 | AI/ML IN APP ⭐ | 6 | 3 | 0 | 3 |
| **TOTAL** | | **252** | **171** | **10** | **71** |

**72% automatable** (auto + probe) → 181 SaaS-scanner candidates.

---

## §1 — APP BINARY (Static Analysis)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | APK decompile (Smali + Java) | apktool, jadx | ✅ |
| 2 | IPA unpack + full Mach-O class-dump | unzip, class-dump-z, otool | ✅ |
| 3 | Android Manifest audit (debuggable, allowBackup, exported) | AAPT, xml parse | ✅ |
| 4 | Info.plist audit (ATS, schemes, capabilities) | plistlib | ✅ |
| 5 | network_security_config.xml audit | xml parse | ✅ |
| 6 | Hardcoded secret extraction (AWS / Firebase / JWT / Stripe) | apkleaks, trufflehog, regex | ✅ |
| 7 | Hardcoded URL / endpoint dump | ripgrep | ✅ |
| 8 | Smali patching → resign → reinstall | apktool + jarsigner | 👤 |
| 9 | Repackaging / trojanizing legit APK | apktool + custom payload | 👤 |
| 10 | Resource tampering (strings, assets, layouts) | apktool | 👤 |
| 11 | adb backup extraction | `adb backup com.app` | ✅ |
| 12 | Native lib hardening (NX, PIE, RELRO, canary) | checksec, otool | ✅ |
| 13 | Mach-O / ELF reverse engineering | Ghidra, Hopper, IDA | 👤 |
| 14 | Symbol stripping audit | nm, strings | ✅ |
| 15 | Bytecode malware signatures | Quark-Engine | ✅ |
| 16 | MobSF aggregate scan | MobSF CLI | ✅ |
| 17 ⭐ | FileProvider grant-uri wildcard misconfig | manifest parse | ✅ |
| 18 ⭐ | iOS Privacy Manifest (PrivacyInfo.xcprivacy) audit | plist parse | ✅ |
| 19 ⭐ | Flutter / React Native bundle extraction | reflutter, react-native-decompiler | ✅ |
| 20 ⭐ | WebAssembly module extraction (.wasm in assets) | wabt, wasm-decompile | ✅ |

---

## §2 — RESILIENCE (Static Detection)

*[Renamed from RUNTIME. True dynamic runtime is §2b, deferred to Phase 4 device farm.]*

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 21 | Anti-debug control presence (ptrace, isDebuggerConnected) | smali grep | ✅ |
| 22 | Root detection presence (RootBeer, custom checks) | smali grep | ✅ |
| 23 | Jailbreak detection presence (Cydia paths, fork, dyld_image_count) | class-dump | ✅ |
| 24 | Emulator detection presence (Build.FINGERPRINT, sensors) | smali grep | ✅ |
| 25 | Frida detection presence (gum-js-loop, port 27042, libfrida) | smali + native scan | ✅ |
| 26 | Play Integrity / App Attest integration check | smali API usage | ✅ |
| 27 ⭐ | Code obfuscation detection (ProGuard / R8 / DexGuard markers) | bytecode entropy | ✅ |
| 28 ⭐ | App signature verification in code (tamper detect presence) | smali grep | ✅ |
| 29 ⭐ | iOS code-signing entitlements audit | codesign -d --entitlements | ✅ |
| 30 ⭐ | SafetyNet legacy usage (deprecated, flag) | smali grep | ✅ |
| 31 | Xposed / LSPosed detection presence | smali grep | ✅ |
| 32 | JNI bridge presence audit | native lib enum | ✅ |
| 33 | DexClassLoader usage (dynamic loading risk) | smali grep | ✅ |
| 34 ⭐ | Anti-VM tricks (CPU / sensor checks) | smali grep | ✅ |

---

## §2b — RUNTIME / IN-MEMORY *(Phase 4 — device farm deferred)*

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 35 | Frida method hooking | Frida + frida-server | ✅ (probe) |
| 36 | Objection workflows (auto-bypass kit) | Objection | ✅ (probe) |
| 37 ⭐ | Frida Gadget injection (no-root) | apk-mitm + Frida Gadget | ✅ (probe) |
| 38 | LLDB / GDB live debugging | LLDB, GDB | 👤 |
| 39 | Memory dumping (keys, tokens) | Fridump, gcore | 👤 |
| 40 | Method swizzling (Obj-C) | Frida, Theos | 👤 |
| 41 ⭐ | r2frida (Radare2 + Frida hybrid) | r2frida | 👤 |
| 42 | Anti-debug bypass | Frida patch | ✅ (probe) |
| 43 | Root detection bypass | Frida + Magisk Shamiko | ✅ (probe) |
| 44 | Jailbreak detection bypass | Liberty Lite, A-Bypass | 👤 |
| 45 | Emulator detection bypass | Shamiko | 👤 |
| 46 | Play Integrity / Attest bypass | Play Integrity Fix module | 👤 |
| 47 | DexClassLoader runtime inspection | Frida | 👤 |
| 48 | JNI bridge hooking | Frida + libc interceptor | 👤 |

---

## §3 — STORAGE (Data-at-Rest)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 49 | SharedPreferences scraping | adb shell + cat | ✅ |
| 50 | SQLite database dump | sqlite3 | ✅ |
| 51 | SQLCipher key extraction | grep + Frida | ✅ |
| 52 | Realm database dump | Realm Studio | 👤 |
| 53 | Core Data inspection (iOS) | sqlite3 | 👤 |
| 54 | Android Keystore key extraction | Frida hook KeyStore | 👤 |
| 55 | iOS Keychain dump (jailbroken) | keychain-dumper | 👤 |
| 56 | Plist scraping (iOS prefs) | plistlib | ✅ |
| 57 | App-switcher screenshot leak (FLAG_SECURE) | manifest + smali | ✅ |
| 58 | WebView cache scraping | adb + grep | ✅ |
| 59 | Image / video cache leak | filesystem scan | ✅ |
| 60 | Logcat / NSLog token leaks | adb logcat, idevicesyslog | ✅ |
| 61 | Clipboard snooping | ClipboardManager audit | ✅ |
| 62 | External storage data | manifest perm + scoped storage | ✅ |
| 63 | Backup extraction (adb / iTunes) | adb backup, iMazing | ✅ |
| 64 ⭐ | Direct Boot data leak (Android 7+ pre-unlock) | manifest + smali | ✅ |
| 65 ⭐ | iOS App Groups shared container leak | entitlements + code | ✅ |
| 66 ⭐ | iCloud Drive / CloudKit data classification | entitlements + plist | ✅ |
| 67 ⭐ | MediaStore data leakage (Android Q+) | manifest + smali | ✅ |
| 68 ⭐ | Scoped Storage compliance (Android 11+) | manifest audit | ✅ |

---

## §4 — CRYPTO

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 69 | Weak algo detection (DES, RC4, MD5, SHA1) | ripgrep | ✅ |
| 70 | AES/ECB mode flag | smali pattern | ✅ |
| 71 | Hardcoded keys / IVs | entropy + regex | ✅ |
| 72 | Insecure PRNG (java.util.Random) | smali AST | ✅ |
| 73 | Custom crypto detection (XOR loops, homebrew) | pattern match | ✅ |
| 74 | TLS version downgrade | network probe | ✅ |
| 75 | Certificate validation bypass (TrustManager) | smali grep | ✅ |
| 76 | Crypto oracle (padding, timing) | Burp | 👤 |
| 77 | Side-channel key recovery (power, EM) | ChipWhisperer | 👤 |
| 78 ⭐ | Hardware-backed Keystore usage (TEE / Secure Enclave) | smali grep | ✅ |
| 79 ⭐ | Post-Quantum Crypto (PQC) readiness check | algorithm enumeration | ✅ |
| 80 ⭐ | Key rotation cadence detection (hardcoded keys timestamp) | smali + metadata | ✅ |

---

## §5 — NETWORK / TRAFFIC

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 81 | MITM proxy (Burp / mitmproxy / Caido) | Burp Suite Pro | 👤 |
| 82 | SSL pinning bypass — Frida CodeShare | Frida | ✅ (probe) |
| 83 | SSL pinning bypass — Objection | Objection | ✅ (probe) |
| 84 ⭐ | SSL pinning bypass — apk-mitm (no-root patch) | apk-mitm | ✅ (probe) |
| 85 | SSL pinning bypass — SSLKillSwitch3 (iOS) | tweak | 👤 |
| 86 | Cleartext HTTP detection | grep + manifest | ✅ |
| 87 | ATS / NetworkSecurityConfig audit | plist / xml | ✅ |
| 88 | DNS rebinding attack | rebind server | 👤 |
| 89 | Rogue Wi-Fi / Evil twin | hostapd + dnsmasq | 👤 |
| 90 | Captive portal HTML/JS injection | bettercap | 👤 |
| 91 | BLE traffic sniffing | Ubertooth, nRF | 👤 |
| 92 | BLE replay / spoofing | gatttool, btlejack | 👤 |
| 93 ⭐ | Bluetooth Classic SDP + PIN audit | btscanner | 👤 |
| 94 | NFC relay attack | Proxmark3, Flipper Zero | 👤 |
| 95 | NFC tag cloning | NFC Tools, Proxmark | 👤 |
| 96 | Cellular IMSI catching | Stingray, OpenBTS | 👤 |
| 97 | SS7 / Diameter signalling abuse | SigPloit | 👤 |
| 98 | Endpoint extraction → backend pivot | regex + dedup | ✅ |
| 99 ⭐ | HTTP/2 + gRPC traffic interception | mitmproxy / Burp | 👤 |
| 100 ⭐ | WebSocket security audit (WSS pinning, origin) | code + traffic | ✅ |
| 101 ⭐ | CORS misconfig on mobile-facing APIs | backend probe | ✅ |
| 102 ⭐ | HSTS / HPKP headers audit | backend probe | ✅ |
| 103 ⭐ | OCSP / CRL stapling check | TLS probe | ✅ |
| 104 ⭐ | DoH / DoT support detection | DNS probe | ✅ |
| 105 ⭐ | QUIC / HTTP/3 audit | network probe | ✅ |

---

## §6 — IPC / PLATFORM

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 106 | Exported activity hijack | `am start` + manifest | ✅ |
| 107 | Intent redirection | manifest analysis + PoC | ✅ |
| 108 | Content provider SQLi | `content://` query | ✅ |
| 109 | Content provider path traversal | crafted URI | ✅ |
| 110 | Broadcast receiver injection | `am broadcast` | ✅ |
| 111 | Sticky broadcast eavesdrop | smali audit | ✅ |
| 112 | Deep-link hijack (custom scheme) | competing app | ✅ |
| 113 | App-link hijack (assetlinks.json) | DNS / cert audit | ✅ |
| 114 | iOS URL scheme abuse | LSApplicationQueriesSchemes | ✅ |
| 115 | iOS Universal Link hijack | apple-app-site-association | ✅ |
| 116 | Tapjacking / overlay attack | SYSTEM_ALERT_WINDOW | ✅ |
| 117 | Pasteboard sniffing (iOS background) | NSPasteboard audit | ✅ |
| 118 | XPC service abuse (iOS) | XPC interface enum | 👤 |
| 119 | Drozer module enumeration | Drozer | ✅ |
| 120 ⭐ | PendingIntent hijack (Strandhogg-class) | smali + manifest | ✅ |
| 121 ⭐ | FileProvider grant-uri wildcard | manifest | ✅ |
| 122 ⭐ | Implicit intent data leak (sensitive extras) | smali | ✅ |
| 123 ⭐ | Notification Listener abuse (OTP theft pattern) | manifest perm | ✅ |
| 124 ⭐ | Autofill service abuse | manifest service | ✅ |
| 125 ⭐ | Custom Tabs hijack (auth flow MITM) | smali grep | ✅ |
| 126 ⭐ | App Shortcuts hijack | manifest + smali | ✅ |
| 127 ⭐ | Slice abuse (Android) | manifest provider | ✅ |
| 128 ⭐ | iOS App Extensions abuse (Share / Today / Action) | Info.plist enum | ✅ |
| 129 ⭐ | SiriKit / Shortcuts intent abuse | entitlements | ✅ |
| 130 ⭐ | HandOff / Continuity attack surface | entitlements | ✅ |
| 131 ⭐ | DocumentPicker / Files app data exposure | entitlements + plist | ✅ |

---

## §7 — WEBVIEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 132 | addJavascriptInterface RCE | smali grep | ✅ |
| 133 | `file://` scheme abuse | setAllowFileAccess check | ✅ |
| 134 | WebView XSS | inject + localStorage steal | ✅ |
| 135 | Insecure URL loading (shouldOverrideUrlLoading) | smali audit | ✅ |
| 136 | UXSS via WebView | crafted page | 👤 |
| 137 | Mixed content load | WebSettings audit | ✅ |
| 138 | WKWebView bridge bypass (postMessage) | code audit | 👤 |
| 139 ⭐ | Cordova / Capacitor / Ionic bridge injection | bundle parse | ✅ |
| 140 ⭐ | Service Worker registration in WebView (persistence) | smali + bundle | ✅ |
| 141 ⭐ | localStorage / IndexedDB exposure across origins | bundle analysis | ✅ |
| 142 ⭐ | getUserMedia abuse (camera / mic via WebView) | WebSettings audit | ✅ |
| 143 ⭐ | eval() / setTimeout(string) in JS bridge | bundle scan | ✅ |
| 144 ⭐ | CSP / Trusted Types audit in WebView | bundle scan | ✅ |
| 145 ⭐ | WKContentRuleList bypass (iOS) | code audit | 👤 |

---

## §8 — AUTH / SESSION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 146 | Biometric bypass (Frida hook) | Frida | ✅ (probe) |
| 147 | JWT none / alg confusion | Burp | ✅ |
| 148 | JWT weak HS256 secret crack | hashcat | ✅ |
| 149 | OAuth redirect hijack | custom scheme race | ✅ |
| 150 | OAuth state / CSRF bypass | proxy intercept | 👤 |
| 151 | SMS-OTP interception (READ_SMS perm) | manifest audit | ✅ |
| 152 | SIM swap attack | social engineering | 👤 |
| 153 | Push token (FCM / APNs) hijack | token extract + replay | 👤 |
| 154 | Session fixation across logout | manual test | 👤 |
| 155 | Refresh token leakage | log + storage audit | ✅ |
| 156 | Account-lockout bypass (device-id rotation) | proxy | ✅ |
| 157 ⭐ | OAuth PKCE missing (RFC 7636 mandatory) | smali grep | ✅ |
| 158 ⭐ | WebAuthn / FIDO2 misconfig | backend probe | ✅ |
| 159 ⭐ | Passkey implementation flaws | code audit | ✅ |
| 160 ⭐ | Magic link / passwordless bypass | backend probe | 👤 |
| 161 ⭐ | TestFlight abuse (GoldPickaxe-class face theft) | review process | 👤 |
| 162 ⭐ | JWT JKU / X5U SSRF | Burp + backend | ✅ |
| 163 ⭐ | JWT kid path traversal | Burp + backend | ✅ |
| 164 ⭐ | OIDC nonce validation | auth flow probe | ✅ |
| 165 ⭐ | Apple Sign In / Google One Tap CSRF | flow audit | 👤 |
| 166 ⭐ | Account recovery flow weakness | manual test | 👤 |

---

## §9 — BACKEND / API (mobile-facing, OWASP API Top 10 2023 aligned)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 167 | API1: BOLA / IDOR | param swap | ✅ |
| 168 ⭐ | API2: Broken Authentication | backend probe | ✅ |
| 169 ⭐ | API3: BOPLA (Broken Object Property Level Authorization) | JSON tamper | ✅ |
| 170 ⭐ | API4: Unrestricted Resource Consumption (DoS) | load test | ✅ |
| 171 ⭐ | API5: BFLA (Broken Function Level Authorization) | endpoint enum | ✅ |
| 172 ⭐ | API6: Unrestricted Access to Sensitive Business Flows | automation test | 👤 |
| 173 | API7: SSRF (server-side via mobile param) | Webapp scanner | ✅ |
| 174 ⭐ | API8: Security Misconfiguration | backend probe | ✅ |
| 175 ⭐ | API9: Improper Inventory Management (shadow / zombie APIs) | URL diff + history | ✅ |
| 176 ⭐ | API10: Unsafe Consumption of 3rd-party APIs | chain audit | ✅ |
| 177 | Mass assignment | JSON tamper | ✅ |
| 178 | GraphQL introspection abuse | InQL, graphql-cop | ✅ |
| 179 ⭐ | GraphQL field-level auth bypass | query crafting | ✅ |
| 180 ⭐ | GraphQL batching attack (DoS) | query batching | ✅ |
| 181 | Rate-limit bypass (device-id rotation) | header rotation | ✅ |
| 182 | Replay attack (no nonce) | Burp resend | ✅ |
| 183 | Hardcoded admin endpoint discovery | grep decompiled | ✅ |
| 184 | API key reuse across users | account test | 👤 |
| 185 | Mobile-only header trust (X-Device-ID, X-App-Version) | proxy spoof | ✅ |
| 186 ⭐ | IAP receipt forgery (StoreKit2 + Google Play Billing) | backend test | ✅ |
| 187 ⭐ | gRPC reflection abuse (server reflection enabled) | grpcurl | ✅ |
| 188 ⭐ | OAuth introspection endpoint abuse | token enum | ✅ |

---

## §10 — SUPPLY CHAIN / DISTRIBUTION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 189 | Fake app store sideload | manual | 👤 |
| 190 | Malicious SDK detection (ad / tracker / spyware) | Exodus, custom DB | ✅ |
| 191 | Dependency confusion | package registry audit | ✅ |
| 192 | Update-server hijack | smali + cert audit | ✅ |
| 193 | Stalkerware presence check | known-hash DB | ✅ |
| 194 | Third-party SDK CVE check | NVD lookup | ✅ |
| 195 | Compromised signing cert | cert chain verify | ✅ |
| 196 ⭐ | App Defense Alliance (ADA) scan | ADA API | ✅ |
| 197 ⭐ | CASA (Google Play Cloud App Security Assessment) | CASA gate | ✅ |
| 198 ⭐ | Apple Privacy Manifest mismatch (PrivacyInfo.xcprivacy) | plist diff | ✅ |
| 199 ⭐ | Google Data Safety declaration mismatch | Play scrape vs actual | ✅ |
| 200 ⭐ | SBOM accuracy check (declared vs actual SDKs) | diff scan | ✅ |
| 201 ⭐ | SLSA / Sigstore provenance check | supply chain | ✅ |
| 202 ⭐ | Permission drift between app versions | version diff | ✅ |
| 203 ⭐ | App store metadata typosquatting | name similarity | ✅ |
| 204 ⭐ | Ad-tech SDK fraud (MMA / IAB compliance) | SDK audit | ✅ |

---

## §11 — OS / DEVICE / HARDWARE *(split from old §11)*

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 205 | Kernel CVE exploit (Dirty COW, etc.) | Metasploit | 👤 |
| 206 | Zero-click iMessage / WhatsApp RCE (Pegasus-class) | exploit kit | 👤 |
| 207 | Bootloader unlock + custom ROM | OEM-specific | 👤 |
| 208 | USB juice-jacking | malicious cable | 👤 |
| 209 | ADB-over-USB on unlocked device | adb | 👤 |
| 210 | Accelerometer keystroke inference | side-channel research | 👤 |
| 211 | Screen-recording via Accessibility | a11y service audit | ✅ |
| 212 | Accessibility-service abuse (Android banking trojans) | manifest audit | ✅ |
| 213 ⭐ | OS version EOL + security patch lag check | version DB | ✅ |
| 214 ⭐ | Pegasus / Predator / Reign MVT indicators | MVT toolkit | ✅ |
| 215 ⭐ | HarmonyOS NEXT specific attack surface | manifest variant | 👤 |
| 216 ⭐ | Knox / Samsung / OEM-specific bypasses | vendor-specific | 👤 |

---

## §12 — SOCIAL ENGINEERING / DISTRIBUTION-SIDE *(split from old §11)*

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 217 | Smishing (SMS phishing) | social engineering | 👤 |
| 218 | Vishing + fake bank app install | social engineering | 👤 |
| 219 | Quishing (malicious QR) | social engineering | 👤 |
| 220 | Fake MDM profile install (iOS) | configuration profile | 👤 |
| 221 ⭐ | GoldPickaxe-style face data theft (TestFlight + AI face swap) | review + exfil | 👤 |
| 222 ⭐ | AirDrop / Nearby Share / Fast Pair spam abuse | proximity attack | 👤 |
| 223 ⭐ | eSIM swap detection (carrier-level) | carrier coordination | 👤 |
| 224 ⭐ | Profile install via QR / MDM enrollment | config profile | 👤 |
| 225 ⭐ | Phone number leak via HIBP | HIBP API | ✅ |
| 226 ⭐ | Stolen credential reuse on app login (credential stuffing) | breach lookup | ✅ (probe) |

---

## §13 — PRIVACY (MASVS-PRIVACY) ⭐ NEW SECTION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 227 ⭐ | Tracking SDK enumeration (Exodus + custom DB) | bundle scan | ✅ |
| 228 ⭐ | PII handling audit (email / phone / IMEI / IDFA in logs) | smali + log scan | ✅ |
| 229 ⭐ | Permission justification audit (over-asks) | manifest + usage map | ✅ |
| 230 ⭐ | Apple App Tracking Transparency (ATT) compliance | code audit | ✅ |
| 231 ⭐ | Apple Privacy Manifest required-reason API check | plist required entries | ✅ |
| 232 ⭐ | Google Data Safety declaration accuracy | Play scrape vs SDK list | ✅ |
| 233 ⭐ | Cross-app tracking via advertising ID (AAID / IDFA) | smali grep | ✅ |
| 234 ⭐ | Persistent identifier abuse (IMEI, AAID, IDFV) | smali grep | ✅ |
| 235 ⭐ | 3rd-party analytics PII leak (Firebase / Mixpanel / Segment) | bundle scan | ✅ |
| 236 ⭐ | Background location collection | manifest perm + code | ✅ |
| 237 ⭐ | Microphone / camera background access | entitlements + code | ✅ |
| 238 ⭐ | GDPR / DPDP consent flow audit | code + flow | 👤 |

---

## §14 — PAYMENT / IAP ⭐ NEW SECTION

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 239 ⭐ | StoreKit2 receipt validation absence | backend probe | ✅ |
| 240 ⭐ | Google Play Billing receipt validation absence | backend probe | ✅ |
| 241 ⭐ | In-App Purchase replay / forgery | Burp test | ✅ |
| 242 ⭐ | Subscription / entitlement abuse (refund + retain) | flow test | 👤 |
| 243 ⭐ | PCI MPoC compliance (mobile payments on COTS) | code + flow audit | ✅ |
| 244 ⭐ | PCI MASS compliance (mobile app security standard) | mapped audit | ✅ |
| 245 ⭐ | Mobile wallet (Apple Pay / Google Wallet / Samsung Pay) abuse | wallet flow | 👤 |
| 246 ⭐ | Stripe / Razorpay / PayPal SDK misconfig | SDK audit | ✅ |

---

## §15 — AI/ML IN APP ⭐ NEW SECTION (emerging 2025+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 247 ⭐ | CoreML model extraction (iOS .mlmodel) | assets scan | ✅ |
| 248 ⭐ | TF Lite model extraction (Android .tflite) | assets scan | ✅ |
| 249 ⭐ | On-device LLM model leak (Mistral / Phi / Gemma in app) | assets scan | ✅ |
| 250 ⭐ | Prompt injection in app-embedded LLM clients | runtime test | 👤 |
| 251 ⭐ | Federated learning poisoning (model upload abuse) | flow audit | 👤 |
| 252 ⭐ | Model bias / sensitive class detection | model introspection | 👤 |

---

## Compliance / Standards Coverage

| Standard | Sections covered |
|---|---|
| **OWASP MASVS v2 STORAGE** | §3 |
| **OWASP MASVS v2 CRYPTO** | §4 |
| **OWASP MASVS v2 AUTH** | §8 |
| **OWASP MASVS v2 NETWORK** | §5 |
| **OWASP MASVS v2 PLATFORM** | §6, §7 |
| **OWASP MASVS v2 CODE** | §1 |
| **OWASP MASVS v2 RESILIENCE** | §2, §2b |
| **OWASP MASVS v2 PRIVACY** | §13 ⭐ |
| **OWASP Mobile Top 10 (2024)** | §1–§10 |
| **OWASP API Top 10 (2023)** | §9 (#167–176) |
| **NIST SP 800-163 Rev 1** | §1, §3, §4, §5, §10 |
| **PCI MPoC / PCI MASS** | §14 ⭐ |
| **Apple Privacy Manifest (PrivacyInfo.xcprivacy)** | §1 #18, §10 #198, §13 #231 |
| **Google Data Safety + CASA + ADA** | §10 #196–199 |
| **GDPR / DPDP Act 2023** | §13 |
| **App Tracking Transparency (Apple)** | §13 #230 |
| **Play Integrity / App Attest** | §2 #26 |

---

## What's currently in the VulnusLab Mobile module

**Already shipped (4 modules, ~36 scanners):**

| § | Module | Scanners shipped | Coverage |
|---|---|---|---|
| §1 STATIC | `mobile_static` | 12 | 12/14 auto = 86% |
| §2 RESILIENCE | `mobile_runtime` *(rename to mobile_resilience)* | 6 | 6/14 auto = 43% |
| §3 STORAGE | `mobile_storage` | 11 | 11/16 auto = 69% |
| §4 CRYPTO | `mobile_crypto` | 7 | 7/10 auto = 70% |

**Plus 12 passive store/intel scanners (pre-binary recon):**
google_play_app_enumeration, apple_app_store_enumeration, app_version_staleness_check, apk_hardcoded_secrets_scan, github_mobile_secret_leak_scan, firebase_open_database_check, certificate_transparency_mobile_api_discovery, ssl_labs_mobile_api_tls_grade, wayback_machine_mobile_api_endpoint_harvest, virustotal_apk_reputation_check, third_party_sdk_cve_check, shodan_mobile_backend_exposure_check.

**Total VulnusLab mobile auto coverage: ~36/171 = 21% of Full Industry Standard.**

---

## Roadmap to 100% Full Industry Standard

| Phase | Scope | Tech adds | Effort |
|---|---|---|---|
| **Phase 2a** | Patch §1–§4 to 100% (close 17 missing scanners) | +17 scanners | 2 days |
| **Phase 2b** | Ship §5 NETWORK, §6 IPC, §7 WEBVIEW, §8 AUTH, §9 BACKEND | ~95 scanners | 2 weeks |
| **Phase 2c** | Ship §10 SUPPLY, §11 OS, §13 PRIVACY, §14 IAP | ~40 scanners | 1 week |
| **Phase 3** | Ship §15 AI/ML, §12 social, OS hardware audits | ~15 scanners | 3 days |
| **Phase 4** | §2b RUNTIME via device farm (BrowserStack / Sauce Labs / Corellium) | ~8 scanners | deferred |

**Result: 171 auto-able scanners = 95–100% Full Industry Standard mobile pentest SaaS.**

---

## Phase 2a — Quick Wins (§1–§4 patches)

| § | Tech # | Scanner to add | Module path |
|---|---|---|---|
| §1 | #17 | `file_provider_misconfig_audit.py` | tools/mobile_static/tier1_manifest_and_config/ |
| §1 | #18 | `ios_privacy_manifest_audit.py` | tools/mobile_static/tier1_manifest_and_config/ |
| §1 | #19 | `flutter_rn_bundle_audit.py` | tools/mobile_static/tier4_behavioral_and_aggregate/ |
| §1 | #20 | `wasm_module_audit.py` | tools/mobile_static/tier4_behavioral_and_aggregate/ |
| §2 | #27 | `code_obfuscation_audit.py` | tools/mobile_resilience/tier1_anti_tamper/ |
| §2 | #28 | `tamper_detection_presence_audit.py` | tools/mobile_resilience/tier1_anti_tamper/ |
| §2 | #29 | `ios_entitlements_audit.py` | tools/mobile_resilience/tier2_attestation/ |
| §2 | #30 | `safetynet_legacy_audit.py` | tools/mobile_resilience/tier2_attestation/ |
| §2 | #34 | `anti_vm_tricks_audit.py` | tools/mobile_resilience/tier1_anti_tamper/ |
| §3 | #64 | `direct_boot_data_audit.py` | tools/mobile_storage/tier3_perms_and_backup/ |
| §3 | #65 | `ios_app_groups_audit.py` | tools/mobile_storage/tier3_perms_and_backup/ |
| §3 | #66 | `icloud_data_classification_audit.py` | tools/mobile_storage/tier3_perms_and_backup/ |
| §3 | #67 | `mediastore_leak_audit.py` | tools/mobile_storage/tier3_perms_and_backup/ |
| §3 | #68 | `scoped_storage_compliance_audit.py` | tools/mobile_storage/tier3_perms_and_backup/ |
| §4 | #78 | `hw_keystore_usage_audit.py` | tools/mobile_crypto/tier2_keys_and_tls/ |
| §4 | #79 | `pqc_readiness_audit.py` | tools/mobile_crypto/tier1_algo_strength/ |
| §4 | #80 | `key_rotation_cadence_audit.py` | tools/mobile_crypto/tier2_keys_and_tls/ |

---

## References

- **OWASP Mobile Top 10 (2024):** https://owasp.org/www-project-mobile-top-10/
- **OWASP MASVS v2:** https://mas.owasp.org/MASVS/
- **OWASP MASTG:** https://mas.owasp.org/MASTG/
- **OWASP API Security Top 10 (2023):** https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **MobSF:** https://github.com/MobSF/Mobile-Security-Framework-MobSF
- **Frida CodeShare:** https://codeshare.frida.re
- **Objection:** https://github.com/sensepost/objection
- **apk-mitm (no-root SSL bypass):** https://github.com/shroudedcode/apk-mitm
- **reflutter (Flutter RE):** https://github.com/Impact-I/reFlutter
- **Exodus Privacy:** https://reports.exodus-privacy.eu.org/en/info/
- **APK Decompilers:** apktool (https://apktool.org), jadx (https://github.com/skylot/jadx)
- **r2frida:** https://github.com/nowsecure/r2frida
- **MVT (Mobile Verification Toolkit):** https://github.com/mvt-project/mvt
- **Apple Privacy Manifest:** https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
- **Google CASA:** https://appdefensealliance.dev/casa
- **App Defense Alliance:** https://appdefensealliance.dev/
- **PCI MASS (Mobile App Security Standard):** https://www.pcisecuritystandards.org/standards/mobile-application-security-standard/
- **Corellium (virtual iOS/Android):** https://www.corellium.com/
