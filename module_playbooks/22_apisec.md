# API Security Testing — Master Reference (`apisec_ruff`)

**100% Full Industry Standard catalogue** — aligned with OWASP API Top 10 (2023) + OWASP API Security Project + Postman testing canon + 2024–2026 industry additions.

10 sections, 140 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | API Discovery & Inventory | 14 | 13 | 0 | 1 |
| 2 | OWASP API Top 10 (2023) | 22 | 19 | 0 | 3 |
| 3 | Authentication (API-specific) | 14 | 11 | 1 | 2 |
| 4 | Authorization (BOLA/BFLA/BOPLA) | 12 | 9 | 1 | 2 |
| 5 | Rate Limiting & Resource Consumption | 8 | 7 | 0 | 1 |
| 6 | GraphQL Security | 14 | 12 | 0 | 2 |
| 7 | gRPC Security ⭐ | 10 | 8 | 0 | 2 |
| 8 | WebSocket / SSE / WebTransport ⭐ | 12 | 9 | 1 | 2 |
| 9 | SOAP / REST Legacy | 10 | 9 | 0 | 1 |
| 10 | API Supply Chain & Versioning ⭐ | 12 | 11 | 0 | 1 |
| **TOTAL** | | **128** | **108** | **2** | **18** |

---

## §1 — API Discovery & Inventory

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | OpenAPI / Swagger spec discovery | nuclei swagger | ✅ |
| 2 | Postman collection harvesting | gh search + custom | ✅ |
| 3 | GraphQL endpoint discovery | graphw00f | ✅ |
| 4 ⭐ | gRPC endpoint + reflection | grpcurl, grpc-discover | ✅ |
| 5 ⭐ | WebSocket endpoint discovery | crawler + custom | ✅ |
| 6 ⭐ | SSE endpoint discovery | curl + crawler | ✅ |
| 7 | JS bundle API endpoint extract | linkfinder + custom | ✅ |
| 8 | Mobile API endpoint extract | apkleaks + decompile | ✅ |
| 9 | API gateway fingerprint | nuclei + custom | ✅ |
| 10 ⭐ | API inventory diff (shadow/zombie APIs) | URL diff + version | ✅ |
| 11 | API documentation crawl | crawler + custom | ✅ |
| 12 | GitHub-leaked API endpoint search | gh search | ✅ |
| 13 | Wayback Machine API URL harvest | waybackurls | ✅ |
| 14 | Manual API workflow mapping | analyst + Postman | 👤 |

---

## §2 — OWASP API Top 10 (2023)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | API1: BOLA / IDOR | autorize, custom | ✅ |
| 16 | API2: Broken Authentication | jwt_tool, custom | ✅ |
| 17 ⭐ | API3: BOPLA (Object Property Level Authz) | JSON tamper | ✅ |
| 18 ⭐ | API4: Unrestricted Resource Consumption | locust + custom | ✅ |
| 19 ⭐ | API5: BFLA (Function Level Authz) | endpoint enum + roles | ✅ |
| 20 ⭐ | API6: Unrestricted Sensitive Business Flow | manual + automation | 👤 |
| 21 | API7: SSRF | ssrfmap, Burp Collaborator | ✅ |
| 22 ⭐ | API8: Security Misconfig (CORS, errors) | nuclei + custom | ✅ |
| 23 ⭐ | API9: Improper Inventory Mgmt | URL diff + history | ✅ |
| 24 ⭐ | API10: Unsafe Consumption of 3rd-party APIs | chain audit | ✅ |
| 25 | OpenAPI spec auto-fuzz | restler, schemathesis | ✅ |
| 26 | Mass assignment | JSON property fuzz | ✅ |
| 27 | Replay attack (no nonce) | Burp resend | ✅ |
| 28 | Hardcoded admin endpoint discovery | grep + decompile | ✅ |
| 29 | API key reuse across users | account test | 👤 |
| 30 | Mobile-only header trust (X-Device-ID) | proxy spoof | ✅ |
| 31 ⭐ | IAP receipt forgery (StoreKit2/Play Billing) | backend test | ✅ |
| 32 ⭐ | API versioning skew (old v1 vulnerable) | URL enum + diff | ✅ |
| 33 ⭐ | API webhook SSRF | callback-URL injection | ✅ |
| 34 ⭐ | OAuth introspection abuse | token enum | ✅ |
| 35 | Manual business-logic chain | analyst | 👤 |
| 36 | API spec-vs-impl drift detection | spec compare | ✅ |

---

## §3 — Authentication (API-specific)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 37 | Basic auth over HTTP | nuclei + custom | ✅ |
| 38 | API key in URL/header leak | regex + log | ✅ |
| 39 | JWT none / alg confusion | jwt_tool | ✅ |
| 40 | JWT HS256 weak secret | hashcat 16500 | ✅ |
| 41 ⭐ | JWT JKU / X5U SSRF | jwt_tool + Burp | ✅ |
| 42 ⭐ | JWT kid path traversal | jwt_tool | ✅ |
| 43 | OAuth redirect_uri hijack | custom + Burp | ✅ |
| 44 ⭐ | OAuth PKCE missing (RFC 7636) | smali grep + custom | ✅ |
| 45 ⭐ | OIDC nonce validation | flow probe | ✅ |
| 46 | mTLS misconfig (cert validation) | openssl + custom | ✅ |
| 47 ⭐ | WebAuthn / FIDO2 misconfig | manual + custom | ✅ (probe) |
| 48 | HMAC signature replay / weak | Burp + custom | ✅ |
| 49 | Bearer token entropy | Burp Sequencer | 👤 |
| 50 | Session-cookie API auth | Burp + manual | 👤 |

---

## §4 — Authorization (BOLA / BFLA / BOPLA)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 51 | BOLA — same-role IDOR | autorize | ✅ |
| 52 | BFLA — function-level (admin route accessible as user) | endpoint enum | ✅ |
| 53 | BOPLA — JSON property mass tamper | Burp + custom | ✅ |
| 54 | Tenant isolation (multi-tenant SaaS) | autorize + manual | ✅ (probe) |
| 55 | Path-based authz bypass | Burp + custom | ✅ |
| 56 | Query-param tampering | Burp Intruder | ✅ |
| 57 | Header-based authz bypass | Burp + custom | ✅ |
| 58 | HTTP verb tampering | nuclei + Burp | ✅ |
| 59 | Resource ID type confusion (UUID → INT) | Burp + custom | ✅ |
| 60 | Manual creative authz bypass | analyst | 👤 |
| 61 | Authentication-only-no-authz pattern detect | manual | 👤 |
| 62 ⭐ | Backend-for-Frontend (BFF) authz bypass | manual + Burp | ✅ |

---

## §5 — Rate Limiting & Resource Consumption

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 63 | Rate-limit absence | custom + Burp | ✅ |
| 64 | Header rotation bypass (X-Forwarded-For) | Burp + custom | ✅ |
| 65 | Distributed rate-limit bypass (multi-IP) | custom | ✅ |
| 66 ⭐ | API4 DoS via large payload | custom | ✅ |
| 67 ⭐ | Cost-DoS (expensive query) | custom | ✅ |
| 68 ⭐ | GraphQL alias / batching cost DoS | InQL | ✅ |
| 69 | Concurrent connections / pool exhaust | locust | ✅ |
| 70 | Manual business-flow rate logic | manual | 👤 |

---

## §6 — GraphQL Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 | Introspection enabled | graphw00f, InQL | ✅ |
| 72 | Suggestion (Did you mean) enabled | InQL | ✅ |
| 73 | Field-level auth bypass | InQL + custom queries | ✅ |
| 74 | Batching attack (DoS) | InQL batch | ✅ |
| 75 | Alias overload (DoS) | InQL alias | ✅ |
| 76 | Query depth / complexity unbounded | InQL custom | ✅ |
| 77 | Directive misuse (@skip, @include) | InQL | ✅ |
| 78 | Cyclical query (recursion) | InQL | ✅ |
| 79 ⭐ | Mutation rate-limit bypass | InQL + custom | ✅ |
| 80 ⭐ | Subscription auth missing | wscat + custom | ✅ |
| 81 ⭐ | Persisted query bypass | manual + Burp | ✅ |
| 82 ⭐ | Apollo Federation gateway abuse | custom + manual | ✅ |
| 83 | Manual schema discovery without introspection | clairvoyance | 👤 |
| 84 | Custom resolver IDOR | manual | 👤 |

---

## §7 — gRPC Security ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 85 ⭐ | gRPC server reflection enabled | grpcurl | ✅ |
| 86 ⭐ | gRPC mTLS misconfig | grpcurl + openssl | ✅ |
| 87 ⭐ | gRPC interceptor bypass | manual + custom | ✅ |
| 88 ⭐ | gRPC-Web parity tests | grpcurl + curl | ✅ |
| 89 ⭐ | Protobuf field-level tamper | custom + grpcurl | ✅ |
| 90 ⭐ | gRPC streaming auth | grpcurl stream | ✅ |
| 91 ⭐ | gRPC error message info-leak | grpcurl + parse | ✅ |
| 92 ⭐ | Custom proto fuzzing | boofuzz + proto | ✅ |
| 93 ⭐ | gRPC envoy/Istio policy bypass | manual + custom | 👤 |
| 94 ⭐ | gRPC service discovery (xDS abuse) | manual | 👤 |

---

## §8 — WebSocket / SSE / WebTransport ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 95 ⭐ | WebSocket origin check missing | wscat + custom | ✅ |
| 96 ⭐ | WebSocket auth post-upgrade | wscat + custom | ✅ |
| 97 ⭐ | WebSocket message injection / fuzz | wscat fuzz | ✅ |
| 98 ⭐ | WebSocket DoS (slow consumer) | custom load | ✅ |
| 99 ⭐ | WebSocket protocol downgrade | manual + Burp | ✅ (probe) |
| 100 ⭐ | SSE origin check missing | curl + custom | ✅ |
| 101 ⭐ | SSE event-stream auth absence | custom + Burp | ✅ |
| 102 ⭐ | WebTransport stream auth | chrome + custom | ✅ |
| 103 ⭐ | WebRTC SDP info-leak | manual + Burp | ✅ |
| 104 ⭐ | Server-Timing header info disclosure | curl + parse | ✅ |
| 105 ⭐ | WebSocket scaling (sticky-session abuse) | manual | 👤 |
| 106 ⭐ | Long-poll vs WebSocket parity | manual | 👤 |

---

## §9 — SOAP / REST Legacy

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 107 | SOAP WSDL discovery + parse | wsdler, custom | ✅ |
| 108 | SOAP injection (XXE, XPath, command) | nuclei + custom | ✅ |
| 109 | XML Signature Wrapping | manual + Burp | ✅ |
| 110 | XXE billion-laughs DoS | nuclei xxe-dos | ✅ |
| 111 | SOAP action tampering | Burp + custom | ✅ |
| 112 | WS-Security misconfig | manual + custom | ✅ |
| 113 | REST verb tampering (GET vs POST) | nuclei + custom | ✅ |
| 114 | REST HEAD / OPTIONS info leak | nuclei + custom | ✅ |
| 115 | REST PATCH / PUT mass-assign | Burp + custom | ✅ |
| 116 | Manual SOAP→REST migration audit | manual | 👤 |

---

## §10 — API Supply Chain & Versioning ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 117 ⭐ | OpenAPI spec hash + signature verify | custom + sigstore | ✅ |
| 118 ⭐ | API SDK dependency vuln | snyk + osv | ✅ |
| 119 ⭐ | Vendored API client CVE check | osv + custom | ✅ |
| 120 ⭐ | API version sunset compliance | doc crawl + custom | ✅ |
| 121 ⭐ | Deprecated endpoint still live | manual + Burp | ✅ |
| 122 ⭐ | API gateway plugin CVE | nuclei + custom | ✅ |
| 123 ⭐ | Kong / Apigee / Tyk config audit | custom | ✅ |
| 124 ⭐ | API key rotation cadence | custom + audit | ✅ |
| 125 ⭐ | OAuth client_secret rotation | manual + audit | ✅ |
| 126 ⭐ | 3rd-party API CVE chain (Stripe/Twilio/Auth0) | manual + NVD | ✅ |
| 127 ⭐ | API marketplace abuse (RapidAPI, etc.) | manual + custom | ✅ |
| 128 ⭐ | API contract testing (Pact) | pact CLI | 👤 |

---

## Compliance Mapping
- **OWASP API Top 10 (2023)** · **OWASP WSTG-API** · **PCI DSS 4.0 §6.4** · **HIPAA** · **SOC 2 CC6** · **GDPR Art. 32** · **NIS2**

## VulnusLab apisec Status
- Status: 🟡 SOON (per modules_2026_inventory.md #21)
- Estimated coverage: 0% (module not yet built)
- Likely overlap: §2, §3, §4 with current webapp module

## Roadmap to 100%
1. Build §1 API discovery + inventory pack (14 scanners)
2. Build §2 OWASP API Top 10 2023 (22 scanners)
3. Build §3–§5 auth/authz/rate-limit (34 scanners)
4. Build §6 GraphQL pack (14 scanners) — leverage existing webapp graphql
5. Build §7–§8 gRPC + WebSocket/SSE (22 scanners) — NEW for 2026
6. Build §9 SOAP legacy (10 scanners) — niche
7. Build §10 API supply chain (12 scanners) — emerging 2025+

## References
- OWASP API Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- 42Crunch API Security Encyclopedia: https://apisecurity.io/encyclopedia/
- PortSwigger Web Security Academy (API): https://portswigger.net/web-security/api-testing
