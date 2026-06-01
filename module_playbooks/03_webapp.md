# Web Application Pentesting — Master Reference (`webapp_ruff`)

**100% Full Industry Standard catalogue** — aligned with OWASP WSTG v4.2 + OWASP Top 10 (2021) + OWASP API Top 10 (2023) + PortSwigger Web Academy methodology + Burp Suite testing canon + 2024–2026 industry additions.

14 sections, 198 techniques.

**Legend:** auto · (probe) detect-auto/exploit-manual · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | Information Gathering | 16 | 14 | 0 | 2 |
| 2 | Configuration & Deployment Mgmt | 12 | 12 | 0 | 0 |
| 3 | Identity Mgmt Testing | 11 | 8 | 1 | 2 |
| 4 | Authentication Testing | 17 | 11 | 2 | 4 |
| 5 | Authorization Testing (BAC/IDOR) | 12 | 9 | 1 | 2 |
| 6 | Session Mgmt Testing | 12 | 10 | 1 | 1 |
| 7 | Input Validation (Injection + XSS) | 22 | 19 | 1 | 2 |
| 8 | Error Handling | 6 | 6 | 0 | 0 |
| 9 | Cryptography Testing | 10 | 9 | 0 | 1 |
| 10 | Business Logic Testing | 12 | 4 | 2 | 6 |
| 11 | Client-Side Testing | 16 | 13 | 0 | 3 |
| 12 | API Testing (OWASP API Top 10 2023) | 22 | 19 | 0 | 3 |
| 13 | Modern Web Surfaces (GraphQL/gRPC/WS/SSE/HTTP3) | 14 | 11 | 1 | 2 |
| 14 | AI / LLM-integrated Web Apps | 8 | 5 | 1 | 2 |
| **TOTAL** | | **190** | **150** | **9** | **30** |

---

## §1 — Information Gathering (WSTG-INFO)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Search engine recon (Google dorks) | googlesearch + dorks | |
| 2 | Web server fingerprinting | whatweb, wafw00f, httpx | |
| 3 | Tech stack identification | Wappalyzer, webanalyze | |
| 4 | WAF / CDN detection | wafw00f, cdn-finder | |
| 5 | robots.txt + sitemap.xml | curl + parse | |
| 6 | Backup / source-code file disclosure | nuclei + custom | |
| 7 | Webserver metadata (HTTP methods) | nmap NSE http-methods | |
| 8 | Application entry-point mapping | Burp Site Map | |
| 9 | Execution paths / endpoint enum | katana, hakrawler | |
| 10 | Framework version fingerprint | Wappalyzer + NVD | |
| 11 | Directory bruteforce | ffuf, feroxbuster, gobuster | |
| 12 | JS endpoint extraction | linkfinder, getjs | |
| 13 | Wayback URL harvest | waybackurls, gau | |
| 14 | Parameter discovery | arjun, paramspider, x8 | |
| 15 | Sourcemap recovery | sourcemapper | |
| 16 | Manual application walkthrough | analyst + Burp | |

---

## §2 — Configuration & Deployment Mgmt (WSTG-CONF)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 17 | Network/infra config review | nmap + custom | |
| 18 | Application platform config | nuclei misconfig | |
| 19 | Sensitive file extension test | nuclei + custom | |
| 20 | Old / unreferenced files | gobuster + wordlist | |
| 21 | HTTP methods / TRACE / OPTIONS | nmap NSE | |
| 22 | HTTP strict-transport-security | curl + parse | |
| 23 | CSP audit | csp-evaluator | |
| 24 | Security headers full audit | securityheaders.com | |
| 25 | CORS misconfiguration | corscanner, nuclei cors | |
| 26 | RIA cross-domain policy (crossdomain.xml, clientaccesspolicy.xml) | curl + parse | |
| 27 | Subresource Integrity (SRI) presence | custom + crawl | |
| 28 | Permissions-Policy / Feature-Policy audit | curl + parse | |

---

## §3 — Identity Management (WSTG-IDNT)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 29 | Role definition test | Burp + manual | |
| 30 | User registration process | Burp + custom | |
| 31 | Account provisioning | Burp + manual | |
| 32 | Account enumeration (login response diff) | Burp Intruder | |
| 33 | Weak username policy | custom + Burp | |
| 34 | Account lockout test | Burp Intruder | |
| 35 | Forgot password flow | Burp + custom | |
| 36 | OIDC userinfo abuse | Burp + custom | |
| 37 | Magic-link entropy / replay | Burp + custom | |
| 38 | OAuth account binding race | manual + Burp | |
| 39 | Multi-tenancy isolation | manual analyst | |

---

## §4 — Authentication Testing (WSTG-ATHN)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 40 | Credentials sent over unencrypted channel | Burp + custom | |
| 41 | Default credentials | hydra + nuclei | |
| 42 | Weak lock-out mechanism | Burp Intruder | |
| 43 | Bypass auth schema (HTTP verb tampering, missing auth) | Burp + custom | |
| 44 | Remember-me functionality | custom + Burp | |
| 45 | Browser cache weakness | custom + Burp | |
| 46 | Weak password policy | custom probe | |
| 47 | Weak security question/answer | manual + Burp | |
| 48 | Weak password change/reset | Burp + custom | |
| 49 | Weaker authentication in alt channel | manual + Burp | |
| 50 | OAuth PKCE missing (RFC 7636) | Burp + custom | |
| 51 | OAuth state CSRF + redirect_uri hijack | Burp + custom | |
| 52 | OIDC nonce validation | Burp + custom | |
| 53 | WebAuthn / Passkey misconfig | manual + custom | (probe) |
| 54 | JWT none / alg confusion | jwt_tool | |
| 55 | JWT weak HS256 secret crack | hashcat 16500 | |
| 56 | JWT JKU / X5U SSRF + kid traversal | jwt_tool + Burp | |

---

## §5 — Authorization Testing (WSTG-ATHZ)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 57 | Directory traversal / file include | nuclei + Burp | |
| 58 | Bypass authorization schema | autorize, AuthMatrix | |
| 59 | Privilege escalation (vertical) | autorize + manual | |
| 60 | IDOR (horizontal authorization) | autorize | |
| 61 | BOPLA (object property level authz) | JSON tamper + Burp | |
| 62 | BFLA (function level authz) | endpoint enum + Burp | |
| 63 | Mass assignment via authenticated POST | Burp + custom | |
| 64 | Path-based authorization | Burp + custom | |
| 65 | Tenant isolation (multi-tenant SaaS) | autorize + manual | (probe) |
| 66 | Manual business-logic privilege chain | analyst + Burp | |
| 67 | Role-based access control matrix audit | AuthMatrix | |
| 68 | Manual creative authz bypass | analyst | |

---

## §6 — Session Management (WSTG-SESS)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 69 | Session token entropy | Burp Sequencer | |
| 70 | Cookie attributes (Secure / HttpOnly / SameSite) | Burp + custom | |
| 71 | Session fixation | Burp + manual | (probe) |
| 72 | Session hijack / fixation across logout | Burp + manual | |
| 73 | Logout functionality | Burp + custom | |
| 74 | Session expiration | Burp + custom | |
| 75 | Concurrent session control | Burp + manual | |
| 76 | Cross-site request forgery (CSRF) | Burp + nuclei csrf | |
| 77 | Session puzzling | manual + Burp | |
| 78 | Session via URL parameter exposure | Burp + custom | |
| 79 | SameSite=None without Secure flag | Burp + custom | |
| 80 | Cookie prefix audit (__Secure / __Host) | Burp + custom | |

---

## §7 — Input Validation (WSTG-INPV)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 81 | XSS reflected | dalfox, XSStrike, nuclei | |
| 82 | XSS stored | manual + Burp | |
| 83 | XSS DOM-based | DOMinator, custom | |
| 84 | XSS via WebSocket / event handlers | manual + Burp | |
| 85 | SQL Injection (classic) | sqlmap, nuclei sqli | |
| 86 | SQL Injection (blind / time-based) | sqlmap --technique=BT | |
| 87 | NoSQL Injection (Mongo, Couch, Redis) | NoSQLMap | |
| 88 | LDAP Injection | nuclei ldap-i | |
| 89 | XPath / XML Injection | nuclei + custom | |
| 90 | Command Injection (OS) | commix, nuclei cmd-i | |
| 91 | Server-Side Template Injection (SSTI) | tplmap, nuclei ssti | |
| 92 | XXE (XML External Entity) | nuclei xxe | |
| 93 | LFI (local file inclusion) | nuclei lfi, custom | |
| 94 | RFI (remote file inclusion) | nuclei rfi | |
| 95 | File upload (unrestricted / RCE) | Burp + nuclei | |
| 96 | HTTP host header injection | nuclei + custom | |
| 97 | HTTP smuggling (CL.TE / TE.CL / TE.TE) | smuggler, h2cSmuggler | |
| 98 | Request splitting / CRLF injection | crlfuzz, nuclei | |
| 99 | Open redirect | nuclei open-redirect | |
| 100 | HTTP/2 rapid reset (CVE-2023-44487) | nuclei + custom | |
| 101 | Prototype pollution (server-side) | nuclei + custom | |
| 102 | Manual chained-injection logic flaw | analyst + Burp | |

---

## §8 — Error Handling (WSTG-ERRH)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 103 | Verbose error messages | Burp + custom | |
| 104 | Stack trace disclosure | nuclei error-detect | |
| 105 | DB error disclosure | sqlmap + custom | |
| 106 | Application logic-error leak | Burp + custom | |
| 107 | Debug info in production | nuclei + custom | |
| 108 | Source-map publication audit | sourcemapper | |

---

## §9 — Cryptography Testing (WSTG-CRYP)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 109 | Transport layer security (TLS audit) | testssl.sh, sslyze | |
| 110 | TLS Heartbleed / POODLE / FREAK / ROBOT | testssl.sh | |
| 111 | TLS version + cipher suite audit | sslscan, nmap NSE | |
| 112 | Weak crypto in app (DES/RC4/MD5/SHA1) | grep + custom | |
| 113 | Padding oracle (POET / CBC-PO) | PadBuster | |
| 114 | Weak random number generator | manual + Burp | |
| 115 | Encryption oracle (decrypt arbitrary) | Burp + custom | (probe) |
| 116 | Post-quantum readiness check | TLS + cert audit | |
| 117 | Certificate Transparency log compliance | crt.sh + audit | |
| 118 | Cookie / token encryption strength | Burp + custom | |

---

## §10 — Business Logic Testing (WSTG-BUSL)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 119 | Data validation logic | manual + Burp | |
| 120 | Request forging | Burp + custom | |
| 121 | Integrity checks (workflow steps) | manual + Burp | |
| 122 | Process timing | Burp + manual | |
| 123 | Function limit (e.g. coupon abuse) | Burp + manual | |
| 124 | Workflow circumvention | analyst + Burp | |
| 125 | Defenses against application misuse | manual | |
| 126 | File upload of unexpected types | Burp + nuclei | |
| 127 | File upload of malicious files (XSS via SVG, etc.) | Burp + custom | |
| 128 | Race condition (limit-overrun) | turbo-intruder | (probe) |
| 129 | E-commerce coupon stacking / refund abuse | manual + Burp | (probe) |
| 130 | SaaS subscription tier bypass | manual + Burp | |

---

## §11 — Client-Side Testing (WSTG-CLNT)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 131 | DOM-based XSS | DOMinator | |
| 132 | JavaScript execution from URL | custom + Burp | |
| 133 | HTML injection | nuclei + custom | |
| 134 | Client-side URL redirect | nuclei + custom | |
| 135 | CSS injection | manual + Burp | |
| 136 | Client-side resource manipulation | manual + Burp | |
| 137 | Cross Origin Resource Sharing (CORS) | corscanner | |
| 138 | Cross Site Flashing | manual | |
| 139 | Clickjacking | clickjack-checker, nuclei | |
| 140 | WebSocket testing | wscat + Burp | |
| 141 | Web messaging (postMessage) | manual + Burp | |
| 142 | Browser storage (localStorage / sessionStorage) | Burp + manual | |
| 143 | Service Worker abuse / persistence | manual + Burp | |
| 144 | Trusted Types CSP audit | custom + Burp | |
| 145 | Browser extension content-script abuse | manual analyst | |
| 146 | Web component (shadow DOM) XSS | manual + Burp | |

---

## §12 — API Testing (OWASP API Top 10 2023)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 147 | API1: BOLA / IDOR | autorize | |
| 148 | API2: Broken Authentication | jwt_tool, custom | |
| 149 | API3: BOPLA | JSON tamper + Burp | |
| 150 | API4: Unrestricted Resource Consumption | locust, custom | |
| 151 | API5: BFLA | endpoint enum + roles | |
| 152 | API6: Unrestricted Sensitive Business Flows | manual + Burp | |
| 153 | API7: SSRF | ssrfmap, nuclei | |
| 154 | API8: Security Misconfig | nuclei + custom | |
| 155 | API9: Improper Inventory (shadow APIs) | URL diff vs spec | |
| 156 | API10: Unsafe 3rd-party API consumption | manual + chain | |
| 157 | OpenAPI / Swagger fuzz | restler, schemathesis | |
| 158 | Mass assignment | JSON property fuzz | |
| 159 | Rate-limit bypass | header rotation | |
| 160 | Replay attack | Burp resend | |
| 161 | API key in URL/log | custom regex | |
| 162 | IAP receipt forgery | backend test | |
| 163 | OAuth introspection abuse | token enum | |
| 164 | GraphQL introspection abuse | graphw00f, InQL | |
| 165 | GraphQL field-level auth bypass | InQL + custom | |
| 166 | GraphQL batching attack (DoS) | InQL + batch | |
| 167 | gRPC reflection abuse | grpcurl | |
| 168 | Manual business-logic chain | analyst + Burp | |

---

## §13 — Modern Web Surfaces NEW (2024+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 169 | gRPC-Web parity tests | grpcurl + curl | |
| 170 | WebSocket origin / auth checks | wscat + custom | |
| 171 | WebSocket message fuzz / injection | wscat fuzz | |
| 172 | Server-Sent Events (SSE) origin check | curl + custom | |
| 173 | HTTP/2 h2c desync smuggling | h2cSmuggler | |
| 174 | HTTP/3 QUIC 0-RTT replay | curl --http3 | |
| 175 | WebTransport stream auth | chrome + custom | (probe) |
| 176 | Server-Timing header info disclosure | curl + parse | |
| 177 | Early Hints (103) abuse | custom + Burp | |
| 178 | WebAssembly module RE in browser | wabt + manual | |
| 179 | Web Crypto API key extraction | manual + browser | |
| 180 | Storage Access API abuse | manual + Burp | |
| 181 | Compute Pressure API fingerprint | manual | |
| 182 | WebGPU side-channel | manual + research | |

---

## §14 — AI / LLM-integrated Web Apps NEW (2025+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 183 | Prompt injection via web form | Garak, PyRIT + Burp | |
| 184 | Indirect prompt injection (RAG poisoning) | custom + Burp | |
| 185 | LLM tool-call abuse (excessive agency) | PyRIT + manual | (probe) |
| 186 | LLM output → XSS (improper handling) | Burp + custom | |
| 187 | LLM system prompt leakage | Garak | |
| 188 | LLM API rate-limit / cost DoS | locust + custom | |
| 189 | Jailbreak via crafted user content | jailbreakbench | |
| 190 | LLM-generated code execution audit | manual + Burp | |

---

## Compliance Mapping
- **OWASP WSTG v4.2:** §1–§11 full coverage
- **OWASP Top 10 (2021):** §3–§11
- **OWASP API Top 10 (2023):** §12
- **OWASP LLM Top 10 (2025):** §14
- **PCI DSS 4.0 §6.4 (web)** · **PCI DSS 4.0 §6.6** · **HIPAA** · **SOC 2 CC6.1** · **GDPR Art. 32**

## VulnusLab Webapp Status (per memory)
- 54 working scanners (per `project_module_inventory.md`)
- 12 OWASP-grade scanners shipped (per `project_session_2026-05-15_webapp_complete.md`): xss, sqli, cmd_injection, lfi, open_redirect, ssrf, xxe, csrf, jwt + earlier (security_headers, exposed_files, cors)
- Estimated coverage: ~60% of full industry standard (need to audit)

## Roadmap to 100%
1. Audit current 54 scanners vs §1–§11 + close gaps
2. Add §12 OWASP API Top 10 2023 full pack (10 new scanners)
3. Add §13 Modern Web Surfaces (14 new — gRPC, WebSocket, SSE, HTTP3)
4. Add §14 LLM-integrated tests (8 new )

## References
- OWASP WSTG v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Burp Suite Pro: https://portswigger.net/burp/pro
- OWASP API Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
