# Authentication Attacks — Master Reference (`auth_attacks_ruff`)

**100% Full Industry Standard catalogue** — MITRE ATT&CK Credential Access (TA0006) + modern auth attack methodology + 2024–2026 industry additions (Passkey, WebAuthn, MFA fatigue).

7 sections, 75 techniques. ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Pass-the-Hash / Pass-the-Ticket | 10 | 9 | 1 |
| 2 | MFA Bypass | 12 | 9 | 3 |
| 3 | OAuth / OIDC Attacks | 14 | 12 | 2 |
| 4 | SAML / Federation Attacks | 8 | 6 | 2 |
| 5 | JWT Attacks | 10 | 10 | 0 |
| 6 | Kerberos Attacks (on-prem AD) | 10 | 9 | 1 |
| 7 | Modern Passwordless (Passkey / WebAuthn) ⭐ | 10 | 6 | 4 |
| **TOTAL** | | **74** | **61** | **13** |

---

## §1 — Pass-the-Hash / Pass-the-Ticket
1 PtH via impacket (-hashes) · 2 PtH via crackmapexec · 3 PtH via evil-winrm · 4 Pass-the-Ticket (Rubeus ptt) · 5 Pass-the-Ticket (mimikatz) · 6 Overpass-the-Hash (Rubeus asktgt + ptt) · 7 Pass-the-Cert (cert-based) ⭐ · 8 Pass-the-Cookie (browser session) ⭐ · 9 Pass-the-Token (cloud OIDC) ⭐ · 10 Manual creative PtX chain 👤

## §2 — MFA Bypass
11 ⭐ EvilGinx2 AiTM phishing (steals session) · 12 ⭐ Modlishka reverse-proxy phishing · 13 ⭐ Browser-in-the-Browser (BitB) · 14 ⭐ MFA fatigue / push bombing 👤 · 15 SMS-OTP SIM swap 👤 · 16 SMS-OTP intercept (READ_SMS perm) · 17 Push notification spam · 18 ⭐ OAuth device-code phishing · 19 ⭐ Recovery flow weakness · 20 Backup-code abuse · 21 Manual MFA-bypass chain 👤 · 22 ⭐ Adversary-in-the-Middle (AiTM) cookie steal

## §3 — OAuth / OIDC Attacks
23 OAuth redirect_uri hijack · 24 OAuth state CSRF · 25 ⭐ OAuth PKCE missing (RFC 7636) · 26 Implicit flow abuse (deprecated, still common) · 27 client_secret leakage · 28 Refresh token rotation absence · 29 ⭐ OIDC nonce validation missing · 30 ⭐ OIDC userinfo abuse · 31 OAuth consent phishing (Microsoft Graph) · 32 ⭐ OAuth device-code phishing · 33 ⭐ Apple Sign In / Google One Tap CSRF · 34 ⭐ OAuth introspection endpoint abuse · 35 Manual OAuth flow audit 👤 · 36 Manual creative OAuth chain 👤

## §4 — SAML / Federation Attacks
37 SAML XML Signature Wrapping (XSW) · 38 SAMLRaider automated tests · 39 SAML Golden Ticket (ADFS cert theft) · 40 SAML response replay · 41 ⭐ SAML 2.0 + JWT bridge confusion · 42 SAML assertion tamper · 43 SAMLter / Burp SAML editor · 44 Manual creative SAML chain 👤

## §5 — JWT Attacks
45 JWT alg=none confusion · 46 JWT HS256 weak secret crack (hashcat 16500) · 47 JWT signature stripping · 48 ⭐ JWT JKU / X5U SSRF · 49 ⭐ JWT kid path traversal · 50 ⭐ JWT kid SQL injection · 51 JWT cross-algorithm confusion (HS256 vs RS256) · 52 JWT expired token replay · 53 JWT key confusion (public→symmetric) · 54 jwt_tool comprehensive scan

## §6 — Kerberos Attacks (on-prem AD)
55 Kerberoasting (GetUserSPNs) · 56 AS-REP Roasting (GetNPUsers) · 57 Unconstrained delegation TGT capture · 58 Constrained delegation S4U · 59 RBCD via Shadow Credentials · 60 ⭐ Diamond/Sapphire ticket (modify PAC) · 61 Golden ticket (krbtgt forgery) · 62 Silver ticket (service-specific) · 63 ⭐ Targeted Kerberoast (one user) · 64 Manual creative Kerberos chain 👤

## §7 — Modern Passwordless (Passkey / WebAuthn) ⭐ NEW
65 ⭐ WebAuthn / FIDO2 misconfig audit · 66 ⭐ Passkey enumeration · 67 ⭐ Passkey cross-device sync abuse 👤 · 68 ⭐ Passkey downgrade attack 👤 · 69 ⭐ Magic-link entropy / replay · 70 ⭐ Passwordless flow audit (Stytch, Auth0) · 71 ⭐ Account-recovery flow weakness · 72 ⭐ TOTP secret leak (if stored) · 73 ⭐ Manual Passkey phishing 👤 · 74 ⭐ Manual creative passwordless chain 👤

---

## VulnusLab Status
- 🟡 SOON (module #16) · Planned: MFA Bypass, Pass-the-Hash, Pass-the-Ticket, Keylog Detection
- Coverage: ~0%

## Roadmap to 100%
Build §1 PtX (10) → §2 MFA bypass (12 ⭐) → §3 OAuth (14) → §4 SAML (8) → §5 JWT (10) → §6 Kerberos (10) → §7 Passkey ⭐ (10)

## References
- jwt_tool: https://github.com/ticarpi/jwt_tool · EvilGinx2: https://github.com/kgretzky/evilginx2 · Modlishka: https://github.com/drk1wi/Modlishka · SAMLRaider · Rubeus · impacket · mimikatz · OAuth 2.0 Security BCP: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
