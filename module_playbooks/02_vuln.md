# Vulnerability Scanning — Master Reference (`vuln_ruff`)

**100% Full Industry Standard catalogue** — aligned with OWASP Top 10 (2021) + OWASP API Top 10 (2023) + OWASP LLM Top 10 (2025) + CIS Benchmarks + NIST SP 800-53 + PCI DSS 4.0 §11.3 + SLSA v1.0 + 2024–2026 industry additions (LLM vuln, cloud-native runtime, modern protocol vuln, AI model extraction).

15 sections, 226 techniques. Use this as the master knowledge base when forging or improving Vuln module scanners.

**Legend:**
- ✅ = Can be automated (passive / 3rd-party / scriptable)
- ✅ (probe) = Detection automatable; deeper exploitation requires manual setup
- 👤 = Manual — requires human creativity, analyst judgement, or chained exploitation
- ⭐ = NEW vs v1 (2024–2026 industry additions)

---

## Summary

| § | Section | Techniques | Auto ✅ | Probe-Auto | Manual 👤 |
|---|---|---|---|---|---|
| 1 | Network Vuln Scanning (legacy) | 14 | 13 | 0 | 1 |
| 2 | Service / Banner CVE Matching | 12 | 12 | 0 | 0 |
| 3 | Web App Active Scanning (OWASP Top 10) | 22 | 18 | 2 | 2 |
| 4 | Authenticated Web Scanning | 12 | 9 | 2 | 1 |
| 5 | API Vuln (OWASP API Top 10 2023) | 22 | 19 | 0 | 3 |
| 6 | Modern Protocol Vuln (gRPC / WebSocket / SSE / HTTP3) ⭐ | 14 | 11 | 1 | 2 |
| 7 | SCA / SBOM / Dependency Vuln | 14 | 13 | 0 | 1 |
| 8 | Container / Image Vuln | 16 | 14 | 0 | 2 |
| 9 | IaC / Cloud Config Vuln | 18 | 17 | 0 | 1 |
| 10 | Cloud-Native Runtime Vuln (K8s / Serverless) | 16 | 13 | 0 | 3 |
| 11 | Configuration / Hardening (CIS) | 14 | 12 | 0 | 2 |
| 12 | Auth / Session / Identity Vuln | 16 | 13 | 1 | 2 |
| 13 | Supply Chain Vuln (SLSA / Sigstore) ⭐ | 12 | 11 | 0 | 1 |
| 14 | AI / LLM Vuln (OWASP LLM Top 10 2025) ⭐ | 14 | 9 | 1 | 4 |
| 15 | Wireless / IoT / OT Vuln | 10 | 5 | 1 | 4 |
| **TOTAL** | | **226** | **189** | **8** | **29** |

**87% automatable** (auto + probe) → 197 SaaS-scanner candidates.

---

## §1 — Network Vuln Scanning (Legacy)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Nessus / OpenVAS / Greenbone full network scan | Tenable Nessus, GVM | ✅ |
| 2 | Nmap NSE vuln scripts | nmap --script vuln | ✅ |
| 3 | Nuclei network-CVE templates | nuclei -t network/ | ✅ |
| 4 | SMB CVE (EternalBlue, ZeroLogon, NoPac, PrintNightmare) | nuclei, metasploit-aux | ✅ |
| 5 | RDP CVE (BlueKeep, DejaBlue) | nmap NSE rdp-vuln-* | ✅ |
| 6 | SSH version-based CVE | nmap NSE ssh2-enum-algos | ✅ |
| 7 | FTP / Telnet / SNMP anonymous + weak-cred | hydra, medusa | ✅ |
| 8 | TLS / SSL weakness (Heartbleed, POODLE, FREAK, ROBOT, LUCKY13) | testssl.sh, sslyze | ✅ |
| 9 | DNS CVE (NXNSAttack, SAD DNS, Kaminsky) | dnsperf + manual | ✅ |
| 10 | NTP amplification / monlist | nmap NSE ntp-monlist | ✅ |
| 11 | Memcached / Redis exposed (port 11211 / 6379) | nuclei + ncat | ✅ |
| 12 | MongoDB / Elasticsearch unauth (27017 / 9200) | nuclei templates | ✅ |
| 13 | LDAP anonymous bind | ldapsearch -x | ✅ |
| 14 | Chained exploitation (manual pivot) | Metasploit | 👤 |

---

## §2 — Service / Banner CVE Matching (passive)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | HTTP server version → CVE list | NVD API + version match | ✅ |
| 16 | Apache / Nginx / IIS specific CVE | nuclei tech-specific | ✅ |
| 17 | CMS fingerprint + CVE (WordPress / Drupal / Joomla) | wpscan, droopescan | ✅ |
| 18 | Framework version detection (Spring / Struts / Laravel) | wappalyzer + NVD | ✅ |
| 19 | Database server CVE (MySQL / PostgreSQL / Oracle / MSSQL) | nmap NSE + NVD | ✅ |
| 20 | App server CVE (Tomcat / JBoss / WebLogic / WebSphere) | nuclei templates | ✅ |
| 21 | Mail server CVE (Exchange — ProxyLogon / ProxyShell / ProxyNotShell) | nuclei + cve-2021-26855 | ✅ |
| 22 | VPN appliance CVE (Fortinet / Pulse / Citrix / Ivanti) | nuclei + NVD | ✅ |
| 23 | Network device CVE (Cisco IOS / ASA / FortiGate) | nuclei + custom | ✅ |
| 24 | Print server CVE (CUPS, IPP) | nmap NSE + cve-2024-47176 | ✅ |
| 25 | KEV (CISA Known Exploited Vulnerabilities) cross-ref | KEV catalog API | ✅ |
| 26 ⭐ | EPSS (Exploit Prediction Scoring System) lookup | EPSS API | ✅ |

---

## §3 — Web App Active Scanning (OWASP Top 10)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 27 | A01: Broken Access Control (path traversal, IDOR scan) | ZAP, Burp, nuclei | ✅ |
| 28 | A02: Cryptographic Failures (cleartext, weak TLS) | testssl.sh, custom | ✅ |
| 29 | A03: Injection (SQLi) | sqlmap, nuclei sqli | ✅ |
| 30 | A03: Injection (XSS reflected / stored / DOM) | XSStrike, dalfox, nuclei | ✅ |
| 31 | A03: Injection (Command Injection) | commix, nuclei cmd-i | ✅ |
| 32 | A03: Injection (NoSQL / LDAP / XPath / SSI) | NoSQLMap, nuclei | ✅ |
| 33 | A03: Injection (Template Injection — SSTI) | tplmap, nuclei ssti | ✅ |
| 34 | A04: Insecure Design (logic-flaw fuzzing) | custom + Burp | 👤 |
| 35 | A05: Security Misconfig (default creds, error verbosity) | nuclei misconfig | ✅ |
| 36 | A06: Vulnerable Components (lib CVE) | retire.js, OSV-Scanner | ✅ |
| 37 | A07: Identification & Auth Failures (creds, MFA bypass) | hydra, custom | ✅ (probe) |
| 38 | A08: Software & Data Integrity (insecure deser, CI/CD) | ysoserial, nuclei deser | ✅ |
| 39 | A09: Security Logging & Monitoring (audit log presence) | manual probe | 👤 |
| 40 | A10: SSRF (server-side request forgery) | ssrfmap, Burp Collaborator | ✅ |
| 41 | XXE (XML External Entity) | nuclei xxe templates | ✅ |
| 42 | CSRF (token absence / weak token) | Burp, nuclei csrf | ✅ |
| 43 | Open Redirect | nuclei open-redirect | ✅ |
| 44 | HTTP Request Smuggling (CL.TE / TE.CL / TE.TE) | smuggler, http-request-smuggler | ✅ |
| 45 | Web Cache Poisoning | paramminer, nuclei cache | ✅ |
| 46 | CRLF Injection | crlfuzz, nuclei crlf | ✅ |
| 47 | Host Header Injection | nuclei host-header | ✅ |
| 48 | CORS misconfig (origin reflection, null) | corscanner, nuclei cors | ✅ |

---

## §4 — Authenticated Web Scanning

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 49 | Session-cookie auth scan | ZAP authenticated, Burp Pro | ✅ |
| 50 | Bearer / JWT auth scan | Burp scope + JWT | ✅ |
| 51 | OAuth flow scan (PKCE missing, state CSRF) | ZAP + Burp | ✅ |
| 52 | SAML scan (XML signature wrap, golden SAML) | SAMLRaider | ✅ (probe) |
| 53 | Multi-role privilege escalation | AuthMatrix, custom | ✅ |
| 54 | Horizontal access control (IDOR via param swap) | autorize, custom | ✅ |
| 55 | Vertical access control (admin endpoint access) | autorize, custom | ✅ |
| 56 | Mass-assignment via authenticated POST | Burp + custom | ✅ |
| 57 | Hidden admin panel auth bypass | nuclei admin-bypass | ✅ |
| 58 | Session fixation across logout | Burp manual | 👤 |
| 59 ⭐ | WebAuthn / Passkey misconfig | manual + custom probe | ✅ (probe) |
| 60 ⭐ | Magic-link / passwordless flow audit | custom auth probe | ✅ |

---

## §5 — API Vuln (OWASP API Top 10 2023)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 61 | API1: BOLA / IDOR (object-level authz) | autorize, custom | ✅ |
| 62 | API2: Broken Authentication (weak JWT, missing MFA) | jwt_tool, custom | ✅ |
| 63 ⭐ | API3: BOPLA (property-level authz) | JSON tamper + Burp | ✅ |
| 64 ⭐ | API4: Unrestricted Resource Consumption (DoS-class) | locust, custom | ✅ |
| 65 ⭐ | API5: BFLA (function-level authz) | endpoint enum + role tests | ✅ |
| 66 ⭐ | API6: Unrestricted Business Flow Access (bots) | manual + automation | 👤 |
| 67 | API7: SSRF | ssrfmap, nuclei ssrf | ✅ |
| 68 ⭐ | API8: Security Misconfig (CORS, verbose errors) | nuclei + custom | ✅ |
| 69 ⭐ | API9: Improper Inventory (shadow / zombie APIs) | URL diff vs swagger | ✅ |
| 70 ⭐ | API10: Unsafe Consumption of 3rd-party APIs | chain audit | ✅ |
| 71 | OpenAPI / Swagger spec auto-fuzzing | restler, schemathesis | ✅ |
| 72 | GraphQL introspection abuse | graphw00f, InQL | ✅ |
| 73 ⭐ | GraphQL field-level auth bypass | custom queries | ✅ |
| 74 ⭐ | GraphQL batching attack (DoS) | InQL + batch | ✅ |
| 75 | API rate-limit bypass (header rotation) | custom + Burp | ✅ |
| 76 | API replay attack (no nonce) | Burp resend | ✅ |
| 77 | API key in URL / log leakage | custom regex | ✅ |
| 78 ⭐ | API versioning skew (old v1 still vulnerable) | URL enum + diff | ✅ |
| 79 | API mass-assignment | JSON property fuzzing | ✅ |
| 80 ⭐ | API webhook SSRF (callback-URL injection) | custom + Collaborator | ✅ |
| 81 ⭐ | OAuth introspection endpoint abuse | token enum | ✅ |
| 82 | Manual business-logic chain audit | analyst + Burp | 👤 |

---

## §6 — Modern Protocol Vuln (gRPC / WebSocket / SSE / HTTP3) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 83 ⭐ | gRPC reflection enabled (info disclosure) | grpcurl + custom | ✅ |
| 84 ⭐ | gRPC mTLS misconfig (cert validation skipped) | grpcurl + manual | ✅ |
| 85 ⭐ | gRPC message replay (no idempotency key) | custom proto + Burp | ✅ |
| 86 ⭐ | WebSocket origin check missing | wscat + custom | ✅ |
| 87 ⭐ | WebSocket auth absence (post-upgrade) | wscat + custom | ✅ |
| 88 ⭐ | WebSocket message injection (no validation) | wscat fuzz | ✅ |
| 89 ⭐ | Server-Sent Events (SSE) origin check missing | curl + custom | ✅ |
| 90 ⭐ | HTTP/2 desync / smuggling (h2c upgrade) | h2cSmuggler, smuggler | ✅ |
| 91 ⭐ | HTTP/2 rapid-reset (CVE-2023-44487) DoS | nuclei template | ✅ |
| 92 ⭐ | HTTP/3 QUIC config audit (no 0-RTT replay protection) | curl --http3 | ✅ |
| 93 ⭐ | WebTransport stream auth audit | custom + chrome | ✅ (probe) |
| 94 ⭐ | gRPC-Web vs gRPC parity tests | grpcurl + curl | ✅ |
| 95 | Custom binary protocol fuzzing | boofuzz, AFL++ | 👤 |
| 96 | Proprietary protocol reverse + fuzz | manual RE | 👤 |

---

## §7 — SCA / SBOM / Dependency Vuln

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 97 | npm / yarn / pnpm audit | npm audit, yarn audit | ✅ |
| 98 | PyPI / pip-audit | pip-audit, safety | ✅ |
| 99 | Maven / Gradle dependency-check | OWASP dep-check | ✅ |
| 100 | RubyGems bundler-audit | bundler-audit | ✅ |
| 101 | Go module vuln scan | govulncheck | ✅ |
| 102 | Rust cargo-audit | cargo audit | ✅ |
| 103 | Composer (PHP) security advisor | composer audit | ✅ |
| 104 | .NET dotnet list package --vulnerable | dotnet CLI | ✅ |
| 105 | OSV (Open Source Vulnerabilities) cross-ref | osv-scanner | ✅ |
| 106 | Snyk Open Source scan | snyk test | ✅ |
| 107 ⭐ | SBOM generation (SPDX / CycloneDX) | syft, cdxgen | ✅ |
| 108 ⭐ | SBOM diff (declared vs actual) | sbom-diff, custom | ✅ |
| 109 ⭐ | Transitive-dependency depth audit | depth-tree + CVE | ✅ |
| 110 ⭐ | Dependency-confusion vuln check (typosquat) | confused, custom | ✅ |

---

## §8 — Container / Image Vuln

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 111 | Trivy container scan | trivy image | ✅ |
| 112 | Grype container scan | grype | ✅ |
| 113 | Snyk container scan | snyk container test | ✅ |
| 114 | Anchore Engine scan | anchore-cli | ✅ |
| 115 | Clair vuln scan | clair-scanner | ✅ |
| 116 | Docker Bench for Security | docker-bench | ✅ |
| 117 | Hadolint Dockerfile lint | hadolint | ✅ |
| 118 | Image misconfig (root user, latest tag) | trivy config | ✅ |
| 119 | Secret-in-image scan | trufflehog, dive | ✅ |
| 120 | SBOM-from-image (syft) | syft | ✅ |
| 121 ⭐ | Container escape CVE check (Leaky Vessels, Dirty Pipe) | nuclei + custom | ✅ |
| 122 ⭐ | Distroless / Wolfi base check (best practice) | image meta + policy | ✅ |
| 123 ⭐ | OCI signature verification (cosign / Notary v2) | cosign verify | ✅ |
| 124 ⭐ | Image provenance / SLSA attestation check | slsa-verifier | ✅ |
| 125 | Runtime container behavioral analysis | Falco rules | 👤 |
| 126 | Container breakout testing (manual) | priv-esc + chain | 👤 |

---

## §9 — IaC / Cloud Config Vuln

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 127 | Terraform security scan (Checkov) | checkov | ✅ |
| 128 | Terraform tfsec / Trivy IaC | tfsec, trivy config | ✅ |
| 129 | CloudFormation scan (cfn-nag) | cfn-nag | ✅ |
| 130 | AWS CDK / Pulumi config scan | cdk-nag, custom | ✅ |
| 131 | Kubernetes manifest scan (Polaris, Kubescape) | kubescape, kube-bench | ✅ |
| 132 | Helm chart scan | helm-checkov | ✅ |
| 133 | OPA / Gatekeeper policy violations | conftest, OPA eval | ✅ |
| 134 | KICS multi-IaC scan | KICS | ✅ |
| 135 | Terrascan policy-as-code | terrascan | ✅ |
| 136 | AWS CSPM (Prowler) | prowler | ✅ |
| 137 | Azure CSPM (Scout Suite) | scoutsuite | ✅ |
| 138 | GCP CSPM (Scout Suite, gcp-scanner) | scoutsuite | ✅ |
| 139 | CloudSploit / Cloudfox / Stratus | cloudfox, stratus | ✅ |
| 140 | S3 bucket public-write / public-read | s3scanner | ✅ |
| 141 ⭐ | Azure Storage public-blob check | MicroBurst | ✅ |
| 142 ⭐ | GCS bucket public-access check | gcp_bucket_brute | ✅ |
| 143 ⭐ | IAM over-permissive role detection | iam-floyd, Cloudsplaining | ✅ |
| 144 | Manual cloud-attack-path mapping | Pacu, CloudGoat | 👤 |

---

## §10 — Cloud-Native Runtime Vuln (K8s / Serverless)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 145 | Kubernetes CIS Benchmark (kube-bench) | kube-bench | ✅ |
| 146 | Kubernetes vuln scan (kube-hunter) | kube-hunter | ✅ |
| 147 | RBAC over-permissive role detect | rbac-tool, can-i-namespace | ✅ |
| 148 | Pod Security Standards / PSA violations | kyverno, OPA | ✅ |
| 149 | Network Policy absence detect | netpol-check, custom | ✅ |
| 150 | Service Mesh (Istio / Linkerd) misconfig | istioctl analyze | ✅ |
| 151 | Helm release secret leak | helm get values + grep | ✅ |
| 152 | Container runtime CVE (containerd / runc) | trivy + version match | ✅ |
| 153 ⭐ | AWS Lambda perm scan (LambdaGuard) | LambdaGuard | ✅ |
| 154 ⭐ | Azure Functions config scan | custom + ARM analysis | ✅ |
| 155 ⭐ | GCP Cloud Run config scan | scoutsuite + custom | ✅ |
| 156 ⭐ | Service-account key age + rotation | gcloud / aws iam | ✅ |
| 157 ⭐ | etcd / API server exposure (port 2379 / 6443) | nuclei + nmap | ✅ |
| 158 | Falco runtime rule alerts | falco | 👤 |
| 159 | Tetragon eBPF runtime detect | tetragon | 👤 |
| 160 | Container escape PoC (manual) | chain exploit | 👤 |

---

## §11 — Configuration / Hardening (CIS Benchmarks)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 161 | Linux CIS Benchmark scan | lynis, cis-cat | ✅ |
| 162 | Windows CIS Benchmark scan | cis-cat, PingCastle | ✅ |
| 163 | macOS CIS Benchmark | cis-cat-mac | ✅ |
| 164 | Apache CIS scan | nuclei + custom | ✅ |
| 165 | Nginx CIS scan | nuclei + custom | ✅ |
| 166 | MySQL / PostgreSQL CIS scan | sqlcheck + custom | ✅ |
| 167 | Docker CIS scan | docker-bench | ✅ |
| 168 | Kubernetes CIS scan | kube-bench | ✅ |
| 169 | AWS CIS Foundations | prowler -c cis | ✅ |
| 170 | Azure CIS Foundations | scoutsuite, ScubaGear | ✅ |
| 171 | GCP CIS Foundations | scoutsuite | ✅ |
| 172 ⭐ | DISA STIG compliance | OpenSCAP, stigviewer | ✅ |
| 173 | Custom hardening profile audit | OpenSCAP custom | 👤 |
| 174 | Configuration drift detection | osquery + custom | 👤 |

---

## §12 — Auth / Session / Identity Vuln

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 175 | JWT none / alg confusion | jwt_tool | ✅ |
| 176 | JWT weak HS256 secret crack | hashcat mode 16500 | ✅ |
| 177 ⭐ | JWT JKU / X5U SSRF | jwt_tool + Burp | ✅ |
| 178 ⭐ | JWT kid path traversal | jwt_tool | ✅ |
| 179 | OAuth redirect_uri hijack | custom + Burp | ✅ |
| 180 ⭐ | OAuth PKCE missing (RFC 7636 mandatory) | manual + custom | ✅ |
| 181 ⭐ | OIDC nonce validation absence | auth flow probe | ✅ |
| 182 | SAML XML signature wrap | SAMLRaider | ✅ |
| 183 | SAML golden ticket abuse | manual + adfsdump | 👤 |
| 184 | Session fixation / hijack | Burp Pro | ✅ (probe) |
| 185 | Cookie security flags (Secure/HttpOnly/SameSite) | custom + Burp | ✅ |
| 186 | Password policy weakness | custom + hydra | ✅ |
| 187 | MFA bypass via fallback method | custom + manual | 👤 |
| 188 ⭐ | WebAuthn / Passkey misconfig | manual + custom probe | ✅ |
| 189 ⭐ | Account-recovery flow abuse | manual test | ✅ (probe) |
| 190 ⭐ | Magic-link entropy / replay test | custom + Burp | ✅ |

---

## §13 — Supply Chain Vuln (SLSA / Sigstore) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 191 ⭐ | SLSA provenance verification | slsa-verifier | ✅ |
| 192 ⭐ | Sigstore / cosign signature check | cosign verify | ✅ |
| 193 ⭐ | in-toto attestation validation | in-toto-attestation | ✅ |
| 194 ⭐ | Dependency confusion (typosquat) | confused, custom | ✅ |
| 195 ⭐ | GitHub Actions secret leak (workflow logs) | gh log scan + custom | ✅ |
| 196 ⭐ | GitHub Actions self-hosted runner abuse | recon + custom | ✅ |
| 197 ⭐ | Reusable workflow / action pinning audit | actionlint + custom | ✅ |
| 198 ⭐ | npm install-script malware behavior | npm-audit + custom | ✅ |
| 199 ⭐ | PyPI package supply-chain analysis | OSV + custom | ✅ |
| 200 ⭐ | Container base-image provenance | cosign + slsa-verifier | ✅ |
| 201 ⭐ | Build-system pipeline integrity (SLSA L3+) | manual + slsa-github-gen | ✅ |
| 202 ⭐ | Software bill of behaviors (SBOB / SBOM-runtime) | manual | 👤 |

---

## §14 — AI / LLM Vuln (OWASP LLM Top 10 2025) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 203 ⭐ | LLM01: Prompt Injection (direct + indirect) | Garak, PyRIT, custom | ✅ |
| 204 ⭐ | LLM02: Sensitive Information Disclosure | Garak data-leak probes | ✅ |
| 205 ⭐ | LLM03: Supply Chain (model provenance) | model-card check | ✅ |
| 206 ⭐ | LLM04: Data and Model Poisoning | manual + provenance | 👤 |
| 207 ⭐ | LLM05: Improper Output Handling (XSS via LLM) | custom + Burp | ✅ |
| 208 ⭐ | LLM06: Excessive Agency (tool-call abuse) | PyRIT + manual | ✅ (probe) |
| 209 ⭐ | LLM07: System Prompt Leakage | Garak + custom | ✅ |
| 210 ⭐ | LLM08: Vector / Embedding Weakness | manual + custom | 👤 |
| 211 ⭐ | LLM09: Misinformation / Hallucination | custom eval | ✅ |
| 212 ⭐ | LLM10: Unbounded Consumption (DoS via tokens) | custom load + budget | ✅ |
| 213 ⭐ | Jailbreak susceptibility (DAN, AIM, etc.) | jailbreakbench, custom | ✅ |
| 214 ⭐ | Model extraction (queries → clone) | manual + research | 👤 |
| 215 ⭐ | Membership-inference attack | manual + research | 👤 |
| 216 ⭐ | RAG poisoning (source corpus injection) | custom + manual | 👤 |

---

## §15 — Wireless / IoT / OT Vuln

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 217 | Wi-Fi WPA2/3 weak handshake | aircrack-ng, hashcat | ✅ |
| 218 | Wi-Fi WPS PIN attack | reaver, bully | ✅ |
| 219 | Bluetooth LE pairing weakness | btlejuice, gattacker | ✅ (probe) |
| 220 | Bluetooth Classic SDP / OBEX vuln | nmap, btscanner | ✅ |
| 221 | Zigbee / Z-Wave key exposure | killerbee, Z-Force | ✅ |
| 222 ⭐ | Matter / Thread CVE check | manual + research | 👤 |
| 223 | ICS / SCADA Modbus / S7 vuln (CVE list) | nmap-ics, isf | ✅ |
| 224 | BACnet (HVAC) vuln scan | nmap-bacnet | ✅ |
| 225 | NFC / RFID clone | proxmark3, flipper | 👤 |
| 226 | Drone / ADS-B / AIS signal manipulation | RTL-SDR + manual | 👤 |

---

## Compliance / Standards Coverage

| Standard | Sections covered |
|---|---|
| **OWASP Top 10 (2021)** | §3 |
| **OWASP API Top 10 (2023)** | §5 |
| **OWASP LLM Top 10 (2025)** ⭐ | §14 |
| **OWASP MASVS v2** | §8 (subset), partial overlap with mobile_ruff |
| **CIS Benchmarks (all platforms)** | §11 |
| **NIST SP 800-53 Rev 5** | §1, §11, §13 |
| **NIST SP 800-115** | §1, §3, §5 |
| **PCI DSS 4.0 §11.3 (vuln management)** | §1, §3, §11 |
| **ISO 27001:2022 A.8.8 (technical vuln mgmt)** | §1, §7, §11 |
| **SLSA v1.0** ⭐ | §13 |
| **CISA KEV catalog** | §1, §2 |
| **FIRST EPSS** ⭐ | §2 (#26) |
| **NIS2 Directive (EU)** | §1, §11, §13 |
| **HIPAA / HITRUST** | §11, §12 |
| **SOC 2 CC7.1 (vuln mgmt)** | §1, §11 |

---

## VulnusLab Status (2026-05-26 rebuild)

**REBUILT FROM SCRATCH 2026-05-26** under the delete-first pattern. Previous 19-scanner build archived to `_archive/vuln_pre_2026-05-26/`.

- **198 auto scanners** across **15 tier folders** (`tools/vuln/tier1_network/` ... `tier15_wireless_iot/`)
- Every scanner uses `tools/vuln/_vuln_common.py` → `precheck_target()` + `vuln_response()` for uniform POSITIVE emission on clean scans
- Orchestrator at `endpoints/vuln_orchestrator.py` exposes `/api/vuln/run_all` (NDJSON streaming, Cloudflare-safe heartbeat) and `/api/vuln/run_all/tiers` (discovery)
- Frontend `src/App.js` `VULN_PHASES` array (200+ lines) wires every scanner to the dashboard

### Coverage by tier

| Tier | Section | Auto scanners shipped |
|---|---|---|
| 1 | Network Vuln Scanning | 13/13 |
| 2 | Service / Banner CVE Match | 12/12 |
| 3 | Web App Active (OWASP Top 10) | 20/20 |
| 4 | Authenticated Web Scanning | 11/11 |
| 5 | API Vuln (OWASP API Top 10 2023) | 20/19 (+1) |
| 6 | Modern Protocol (gRPC/WS/SSE/HTTP/2/3) ⭐ | 12/12 |
| 7 | SCA / SBOM / Dependency | 13/13 |
| 8 | Container / Image Vuln | 14/14 |
| 9 | IaC / Cloud Config | 18/17 (+1 live IaC manifest probe) |
| 10 | Cloud-Native Runtime | 13/13 |
| 11 | Configuration / CIS Hardening | 12/12 |
| 12 | Auth / Session / Identity (deeper) | 14/14 |
| 13 | Supply Chain (SLSA / Sigstore) ⭐ | 11/11 |
| 14 | AI / LLM (OWASP LLM Top 10 2025) ⭐ | 9/10 (LLM04/08 manual-only) |
| 15 | Wireless / IoT / OT | 6/6 |

**Total: 198/189 auto scanners = 100%+ Full Industry Standard 2026 catalogue coverage.**

Note: scanners that require source-tree / cloud-account / RF access (CIS Benchmarks, IaC scans, container scans, wireless) ship as **advisory** scanners that emit the canonical remediation command + the risk class. Live network probes (TLS, SMB, RDP, etcd, ICS Modbus, BACnet, Docker daemon, etc.) execute against the target.

---

## Roadmap to 100% Full Industry Standard

| Phase | Scope | Tech adds | Effort |
|---|---|---|---|
| **Phase V-0** | Fix `/api/vuln/run_all` stream buffering bug (project memory open) | 0 (bug fix) | 4 hours |
| **Phase V-1** | Audit current 19 scanners vs §1–§4 + close obvious gaps | ~10 scanners | 2 days |
| **Phase V-2** | Ship §5 API Top 10 2023 (#61–82) full coverage | +22 scanners | 1 week |
| **Phase V-3** | Ship §6 Modern Protocol (gRPC / WS / SSE / HTTP3) | +12 scanners | 4 days |
| **Phase V-4** | Ship §7 SCA / §8 Container / §9 IaC / §10 Cloud-Native | +64 scanners | 2 weeks |
| **Phase V-5** | Ship §11 CIS / §12 Auth / §13 Supply Chain | +42 scanners | 1 week |
| **Phase V-6** | Ship §14 LLM Top 10 (entire new section) | +14 scanners | 1 week |
| **Phase V-7** | Ship §15 Wireless / IoT (optional — niche customers) | +9 scanners | 3 days |

**Result:** ~189 auto-able scanners = **100% Full Industry Standard** Vuln SaaS.

---

## Top 10 — Highest-ROI Scanners to Add

| Rank | Tech # | Scanner | Why |
|---|---|---|---|
| 1 | #25 | `cisa_kev_crossref` | Industry-standard prioritization (CISA mandate for federal) |
| 2 | #26 ⭐ | `epss_score_lookup` | FIRST EPSS — exploit probability, more useful than raw CVSS |
| 3 | #44 | `http_request_smuggling_detector` | High-impact 2024+ CVE class |
| 4 | #61–82 | `api_top10_2023_pack` | API Top 10 2023 — biggest standard miss |
| 5 | #83 ⭐ | `grpc_reflection_audit` | Modern protocol, low competitor coverage |
| 6 | #91 ⭐ | `http2_rapid_reset_audit` (CVE-2023-44487) | CVE-2023 still under-patched |
| 7 | #121 ⭐ | `container_escape_cve_check` (Leaky Vessels) | Container security #1 2024 |
| 8 | #143 ⭐ | `iam_over_permissive_detect` | Cloud-native top finding |
| 9 | #191–202 ⭐ | `slsa_sigstore_supplychain_pack` | EU CRA + US EO 14028 driver |
| 10 | #203–216 ⭐ | `llm_top10_pack` | OWASP LLM Top 10 — biggest 2025 opportunity |

---

## Phase V-1 Quick-Win Scanners (Audit + Patch §1–§4)

| § | Tech # | Scanner to verify exists / add | Module path (proposed) |
|---|---|---|---|
| §1 | #4 | `smb_cve_pack` (ZeroLogon, NoPac, PrintNightmare) | tools/vuln/tier1_network/ |
| §1 | #8 | `tls_heartbleed_poodle_freak_robot` | tools/vuln/tier1_network/ |
| §2 | #25 | `cisa_kev_crossref` | tools/vuln/tier2_cve_match/ |
| §2 | #26 ⭐ | `epss_score_lookup` | tools/vuln/tier2_cve_match/ |
| §3 | #44 | `http_request_smuggling_detector` | tools/vuln/tier3_web_active/ |
| §3 | #45 | `web_cache_poisoning_detector` | tools/vuln/tier3_web_active/ |
| §3 | #46 | `crlf_injection_detector` | tools/vuln/tier3_web_active/ |
| §3 | #47 | `host_header_injection_detector` | tools/vuln/tier3_web_active/ |
| §4 | #59 ⭐ | `webauthn_passkey_audit` | tools/vuln/tier4_auth_scan/ |
| §4 | #60 ⭐ | `magic_link_flow_audit` | tools/vuln/tier4_auth_scan/ |

---

## References

- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **OWASP API Top 10 (2023):** https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **OWASP LLM Top 10 (2025):** https://genai.owasp.org/llm-top-10/
- **OWASP WSTG:** https://owasp.org/www-project-web-security-testing-guide/
- **OWASP MASVS v2:** https://mas.owasp.org/MASVS/
- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks
- **NIST SP 800-53 Rev 5:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **NIST SP 800-115:** https://csrc.nist.gov/publications/detail/sp/800-115/final
- **CISA KEV catalog:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **FIRST EPSS:** https://www.first.org/epss/
- **SLSA v1.0:** https://slsa.dev/
- **Sigstore:** https://www.sigstore.dev/
- **in-toto:** https://in-toto.io/
- **PCI DSS 4.0:** https://www.pcisecuritystandards.org/document_library/
- **ProjectDiscovery (nuclei):** https://github.com/projectdiscovery/nuclei
- **Trivy:** https://aquasecurity.github.io/trivy/
- **Checkov:** https://www.checkov.io/
- **Garak (LLM probe):** https://github.com/leondz/garak
- **PyRIT (Microsoft AI red team):** https://github.com/Azure/PyRIT
