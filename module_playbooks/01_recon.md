# Information Gathering & Recon — Master Reference (`recon_ruff`)

**100% Full Industry Standard catalogue** — aligned with PTES Intelligence Gathering + OWASP WSTG-INFO + NIST SP 800-115 §4.2 + MITRE PRE-ATT&CK + 2025–2026 industry additions (AI/LLM-assisted recon, modern API discovery, supply-chain intel).

13 sections, 184 techniques. Use this as the master knowledge base when forging or improving Recon module scanners.

**Legend:**
- ✅ = Can be automated (passive / 3rd-party / scriptable)
- ✅ (probe) = Detection automatable; deeper exploitation requires manual setup
- 👤 = Manual — requires human creativity, analyst judgement, or hardware
- ⭐ = NEW vs v1 (2024–2026 industry additions)

---

## Summary

| § | Section | Techniques | Auto ✅ | Probe-Auto | Manual 👤 |
|---|---|---|---|---|---|
| 1 | Passive Footprint (no contact) | 15 | 14 | 0 | 1 |
| 2 | DNS Recon | 18 | 16 | 0 | 2 |
| 3 | Subdomain Enumeration | 14 | 12 | 1 | 1 |
| 4 | OSINT / Public Records | 18 | 16 | 0 | 2 |
| 5 | Web App Recon (active, low-touch) | 22 | 18 | 2 | 2 |
| 6 | Cloud Asset Discovery | 17 | 14 | 0 | 3 |
| 7 | Email / People Intel | 15 | 13 | 0 | 2 |
| 8 | Threat Intel / Reputation | 13 | 12 | 0 | 1 |
| 9 | Network / Infrastructure | 17 | 13 | 1 | 3 |
| 10 | Code Repo / Secret Leak | 10 | 9 | 0 | 1 |
| 11 | Dark Web / Breach Intel | 8 | 6 | 0 | 2 |
| 12 | Mobile / IoT Discovery | 9 | 8 | 0 | 1 |
| 13 | AI/LLM-assisted Recon ⭐ | 8 | 5 | 0 | 3 |
| **TOTAL** | | **184** | **156** | **4** | **24** |

**87% automatable** (auto + probe) → 160 SaaS-scanner candidates.

---

## §1 — Passive Footprint (no direct contact)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | WHOIS lookup (registrar, dates, contacts) | whois, RDAP | ✅ |
| 2 | RDAP / IANA TLD allocation | rdap.org, IANA WHOIS | ✅ |
| 3 | ASN lookup (org → IP blocks) | bgp.he.net, asn-lookup | ✅ |
| 4 | IP geolocation + ISP attribution | ipinfo.io, MaxMind | ✅ |
| 5 | Reverse-IP (sibling domains on same host) | hackertarget, ViewDNS | ✅ |
| 6 | Reverse-NS (other domains on same NS) | PassiveTotal, DomainTools | ✅ |
| 7 | Domain age + first-seen | DomainTools, WhoisXML API | ✅ |
| 8 | Historical WHOIS records | DomainTools Iris, ViewDNS | ✅ |
| 9 | DNS history (Passive DNS) | SecurityTrails, Farsight DNSDB | ✅ |
| 10 | Certificate Transparency log search | crt.sh, censys.io | ✅ |
| 11 | Wayback Machine timeline | web.archive.org CDX API | ✅ |
| 12 | Common Crawl index search | commoncrawl.org indexes | ✅ |
| 13 | favicon hash fingerprinting (mmh3) | shodan favicon search | ✅ |
| 14 ⭐ | Subject SAN scraping across all certs | crt.sh JSON + dedupe | ✅ |
| 15 | OSINT framework chain (mind-map traversal) | OSINT Framework, IntelTechniques | 👤 |

---

## §2 — DNS Recon

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 16 | Standard records (A/AAAA/MX/NS/TXT/SOA) | dig, dnsx | ✅ |
| 17 | CAA records (cert authority binding) | dig CAA | ✅ |
| 18 | SPF / DKIM / DMARC analysis | dmarcian, MXToolbox | ✅ |
| 19 | DNSSEC chain validation | delv, dnssec-debugger | ✅ |
| 20 | Zone transfer attempt (AXFR/IXFR) | dig +axfr | ✅ |
| 21 | Reverse DNS sweep (PTR) | dnsx -ptr | ✅ |
| 22 | DNS cache snooping (recursion abuse) | dig +norecurse | ✅ |
| 23 | DNS wildcard detection | dnsx -wcard | ✅ |
| 24 | Subdomain takeover dangling CNAME | subjack, Subzy, nuclei | ✅ |
| 25 | DNS over HTTPS (DoH) / DoT support detect | curl + doh, openssl s_client | ✅ |
| 26 ⭐ | DNS rebinding susceptibility | rebinder.cloud | ✅ |
| 27 ⭐ | DNS poisoning resistance (0x20 random case) | dig +bufsize | ✅ |
| 28 | DNS infrastructure mapping (anycast detect) | RIPE Atlas, dnsperf | ✅ |
| 29 | Mail server enumeration via MX | dig MX | ✅ |
| 30 | DNS load-balancer detection | dig (multiple A) | ✅ |
| 31 | NSEC walking (DNSSEC zone enum) | nsec3walker | ✅ |
| 32 | NXNS attack feasibility | manual / research | 👤 |
| 33 | DNS tunneling detection (entropy) | manual / Splunk | 👤 |

---

## §3 — Subdomain Enumeration

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 34 | Brute-force wordlist | gobuster, ffuf, dnsx | ✅ |
| 35 | Passive aggregation (multiple sources) | subfinder, amass | ✅ |
| 36 | Certificate Transparency mining | crt.sh, censys | ✅ |
| 37 | Search engine scraping (Bing/Google) | theHarvester | ✅ |
| 38 | DNS bruteforce with wildcard handling | shuffledns + dnsx | ✅ |
| 39 | Permutation generation (perm-rules) | altdns, dnsgen | ✅ |
| 40 | OSINT API aggregation | amass enum -passive | ✅ |
| 41 | GitHub search for subdomains | github-subdomains | ✅ |
| 42 | VirusTotal subdomain feed | VT API | ✅ |
| 43 | SecurityTrails / SpyOnWeb / RiskIQ | API access | ✅ |
| 44 | Wayback Machine subdomain extract | waybackurls + parse | ✅ |
| 45 ⭐ | AI-curated wordlist (LLM-generated) | custom curator | ✅ |
| 46 | Subdomain takeover verification | nuclei takeover templates | ✅ (probe) |
| 47 | Manual creative pivot (employee names, internal tooling) | human analyst | 👤 |

---

## §4 — OSINT / Public Records

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 48 | Company registry lookup (SEC EDGAR, OpenCorporates) | SEC EDGAR API | ✅ |
| 49 | Patent search (USPTO, EPO, WIPO) | USPTO, espacenet | ✅ |
| 50 | Trademark search | TESS, EUIPO | ✅ |
| 51 | Job posting scraping (tech stack leak) | LinkedIn Jobs, Indeed scrape | ✅ |
| 52 | LinkedIn employee enumeration | LinkedInt, ScrapedIn | ✅ |
| 53 | Twitter/X public timeline mining | snscrape, Twitter API | ✅ |
| 54 | Facebook / Instagram public posts | Sherlock, OSINT-SAN | ✅ |
| 55 | TikTok username pivot | tiktok-scraper | ✅ |
| 56 | YouTube channel + comment mining | youtube-comment-downloader | ✅ |
| 57 | Reddit user history + subreddit pivot | redditscraper, PullPush | ✅ |
| 58 | GitHub org members + repos | gh api / recon-ng | ✅ |
| 59 | Pastebin / Ghostbin / Hastebin search | psbdmp.ws, pastes.io | ✅ |
| 60 | Discord server / channel enum | Discord intel tools | ✅ |
| 61 | Telegram channel scraping | tg-channel-scraper | ✅ |
| 62 | Sherlock username-across-platforms | Sherlock | ✅ |
| 63 | Maltego transform graphs | Maltego CE | ✅ |
| 64 ⭐ | OSINT Industries aggregator | osint.industries | ✅ |
| 65 | Real-name + photo pivot (creative search) | human analyst | 👤 |

---

## §5 — Web App Recon (active, low-touch)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 66 | HTTP banner / server fingerprint | httpx, whatweb | ✅ |
| 67 | Technology stack detection | Wappalyzer, webanalyze | ✅ |
| 68 | TLS / SSL certificate scan | sslscan, sslyze, testssl.sh | ✅ |
| 69 | TLS Labs / SSL Labs grade | SSL Labs API | ✅ |
| 70 | HTTP security headers audit | securityheaders.com, custom | ✅ |
| 71 | CDN / WAF fingerprinting | wafw00f, cdn-finder | ✅ |
| 72 | Robots.txt + sitemap.xml extraction | curl + parse | ✅ |
| 73 | Security.txt audit | curl /.well-known/security.txt | ✅ |
| 74 | Directory brute-force | ffuf, gobuster, feroxbuster | ✅ |
| 75 | Endpoint extraction (JS file harvest) | linkfinder, getjs, katana | ✅ |
| 76 | Crawl + spider (modern SPA) | katana, hakrawler | ✅ |
| 77 | Wayback Machine URL harvest | waybackurls, gau | ✅ |
| 78 | GitHub-leaked URLs / endpoints | github-endpoints, trufflehog | ✅ |
| 79 | Parameter discovery | arjun, paramspider, x8 | ✅ |
| 80 | JS source-map + sourcemap recovery | sourcemapper, retire.js | ✅ |
| 81 | Hidden parameter (HPP, mass-assign) discovery | arjun -m all | ✅ |
| 82 | GraphQL endpoint discovery + introspection | graphw00f, InQL | ✅ |
| 83 ⭐ | gRPC reflection endpoint discovery | grpcurl, grpc-discover | ✅ |
| 84 ⭐ | WebSocket endpoint discovery | wscat + crawler | ✅ (probe) |
| 85 ⭐ | Server-Sent Events (SSE) endpoint detect | curl + crawler | ✅ (probe) |
| 86 | Origin server discovery (CDN bypass) | CloudFlair, censys IP-pivot | 👤 |
| 87 | Account-bound endpoint enumeration | manual + Burp | 👤 |

---

## §6 — Cloud Asset Discovery

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 88 | S3 bucket enumeration | s3scanner, bucket-stream | ✅ |
| 89 | Azure Blob enumeration | azurehound, MicroBurst | ✅ |
| 90 | GCS bucket enumeration | gcp_bucket_brute | ✅ |
| 91 | DigitalOcean Spaces enum | s3scanner adapted | ✅ |
| 92 | Bucket permission audit (public read/write) | aws s3 ls + ACL | ✅ |
| 93 | CloudFront distribution discovery | dnsrecon + cert pivot | ✅ |
| 94 | Azure App Services discovery | MicroBurst, AADInternals | ✅ |
| 95 | GCP App Engine / Cloud Run discovery | cloud_enum | ✅ |
| 96 | Heroku app enumeration | heroku-osint | ✅ |
| 97 | Vercel / Netlify deployment enum | cloud_enum, certificate pivot | ✅ |
| 98 | Kubernetes API exposure (6443 / 10250) | kube-hunter, masscan | ✅ |
| 99 | Docker registry exposure (5000) | shodan, registry-grab | ✅ |
| 100 | Helm chart / etcd exposure | nuclei templates | ✅ |
| 101 ⭐ | GitHub Actions self-hosted runner discovery | gh api + recon | ✅ |
| 102 ⭐ | Cloud Run / Lambda function URL enum | cloud_enum + custom | ✅ |
| 103 ⭐ | OIDC trust relationship abuse map | manual + cloudfox | 👤 |
| 104 | Cloud admin / IAM role abuse mapping | Pacu, Stratus Red Team | 👤 |

---

## §7 — Email / People Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 105 | Email harvesting from web | theHarvester, hunter.io | ✅ |
| 106 | Hunter.io domain email pattern | Hunter API | ✅ |
| 107 | LinkedIn → email format guess | crosslinked, LinkedInt | ✅ |
| 108 | Email validation (catchall / SMTP) | EmailValidator, MXToolbox | ✅ |
| 109 | Have I Been Pwned breach lookup | HIBP API | ✅ |
| 110 | DeHashed breach search | DeHashed API | ✅ |
| 111 | LeakCheck / Intelligence X breach | LeakCheck API, IntelX | ✅ |
| 112 | Email-to-phone (OSINT pivot) | OSINT Industries, Spokeo | ✅ |
| 113 | Reverse-image search (profile photo) | Yandex, TinEye, Pimeyes | ✅ |
| 114 | Phone number OSINT | PhoneInfoga | ✅ |
| 115 | Email → social profile pivot | Sherlock, Holehe | ✅ |
| 116 ⭐ | Holehe forgot-password enumeration (60+ services) | Holehe | ✅ |
| 117 ⭐ | GHunt — Google account intel | GHunt | ✅ |
| 118 | Manual social engineering pretext build | human + LinkedIn | 👤 |
| 119 | Voice / face profile (vishing prep) | manual | 👤 |

---

## §8 — Threat Intel / Reputation

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 120 | VirusTotal domain / IP / URL / hash | VT API | ✅ |
| 121 | AbuseIPDB reputation | AbuseIPDB API | ✅ |
| 122 | AlienVault OTX indicators | OTX API | ✅ |
| 123 | Shodan host fingerprint | Shodan API | ✅ |
| 124 | Censys host + cert search | Censys API | ✅ |
| 125 | ZoomEye host search | ZoomEye API | ✅ |
| 126 | FOFA / Quake (China-based) | FOFA API | ✅ |
| 127 | URLhaus / MalwareBazaar | abuse.ch API | ✅ |
| 128 | ThreatFox IOC database | abuse.ch ThreatFox | ✅ |
| 129 | MISP threat-intel feed | MISP instance | ✅ |
| 130 | GreyNoise (mass-scan attribution) | GreyNoise API | ✅ |
| 131 ⭐ | InternetDB (free Shodan host info) | InternetDB API | ✅ |
| 132 | Attribution / actor mapping (manual) | analyst + Mandiant Advantage | 👤 |

---

## §9 — Network / Infrastructure Recon

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 133 | Port scan (TCP / SYN) | nmap, masscan, naabu | ✅ |
| 134 | UDP scan (top ports) | nmap -sU | ✅ |
| 135 | Service / version detect | nmap -sV, nuclei | ✅ |
| 136 | OS fingerprinting | nmap -O | ✅ |
| 137 | NSE script scan (vuln detection) | nmap --script vuln | ✅ |
| 138 | Banner grabbing (raw socket) | ncat, banner-grab | ✅ |
| 139 | TLS / mTLS cert chain audit | openssl s_client, sslscan | ✅ |
| 140 | SNMP enumeration | onesixtyone, snmpwalk | ✅ |
| 141 | SMB / NetBIOS enum | enum4linux-ng, nbtscan | ✅ |
| 142 | RPC endpoint mapper enum | rpcclient, rpcdump | ✅ |
| 143 | LDAP enumeration (anon bind) | ldapsearch, windapsearch | ✅ |
| 144 | IPMI / iLO / iDRAC discovery (623 / 443) | nmap NSE, ipmitool | ✅ |
| 145 | VoIP / SIP enumeration | sipvicious, svmap | ✅ |
| 146 | ICS / SCADA discovery (Modbus, S7, BACnet) | nmap-ics, plcscan | 👤 |
| 147 ⭐ | IPv6 reachable host enum | THC-IPv6 toolkit | ✅ (probe) |
| 148 | Network topology mapping (traceroute) | mtr, traceroute, scapy | 👤 |
| 149 | BGP route announcement audit | bgp.he.net + manual | 👤 |

---

## §10 — Code Repo / Secret Leak

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 150 | GitHub code search (secret patterns) | gh api search, trufflehog | ✅ |
| 151 | GitLab / Bitbucket scan | trufflehog, gitleaks | ✅ |
| 152 | npm / PyPI / RubyGems package audit | OSV, snyk advisor | ✅ |
| 153 | Docker Hub image scan | dive, syft, trivy | ✅ |
| 154 | Pastebin code leak | psbdmp + grep | ✅ |
| 155 | NPM dependency confusion vuln check | confusion-finder | ✅ |
| 156 | GitHub Actions secret leak (logs) | actionrunner-leakcheck | ✅ |
| 157 ⭐ | GitHub OAuth app abuse mapping | gh api + custom | ✅ |
| 158 ⭐ | Cargo / Go module typosquat detect | OSV + similarity | ✅ |
| 159 | Manual repo deep-dive (PR comments, gists) | human + grep | 👤 |

---

## §11 — Dark Web / Breach Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 160 | HIBP breach API + paste API | HIBP API | ✅ |
| 161 | DeHashed credential search | DeHashed API | ✅ |
| 162 | Intelligence X paste + leak | IntelX API | ✅ |
| 163 | LeakIX exposed asset feed | LeakIX API | ✅ |
| 164 | Stealer log search (RedLine, Vidar) | russianmarket monitors | ✅ |
| 165 | Ransomware leak-site monitor | ransomwatch.org | ✅ |
| 166 | Tor hidden service crawl | OnionScan, Ahmia | 👤 |
| 167 | Telegram leak-channel monitor | manual + tg-archive | 👤 |

---

## §12 — Mobile / IoT Discovery

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 168 | Google Play app discovery (org-bound) | gplaycli, play-scraper | ✅ |
| 169 | Apple App Store discovery | iTunes Search API | ✅ |
| 170 | Mobile API endpoint extraction (decompile) | mobsf + apkleaks | ✅ |
| 171 | Firebase project enumeration | firebaseenum, custom | ✅ |
| 172 | Mobile backend Shodan pivot | Shodan + favicon | ✅ |
| 173 | IoT device fingerprint (Shodan ports) | Shodan + nuclei | ✅ |
| 174 | UPnP / SSDP discovery | gssdp, nmap-ssdp | ✅ |
| 175 ⭐ | Matter / Thread / Zigbee discovery | killerbee, ZBOSS | ✅ |
| 176 | Drone / ADS-B / AIS passive intercept | RTL-SDR + manual | 👤 |

---

## §13 — AI/LLM-assisted Recon ⭐ NEW SECTION (2025+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 177 ⭐ | LLM-curated wordlist generation | GPT-4o / Claude / Llama | ✅ |
| 178 ⭐ | AI-driven endpoint guessing (path semantics) | custom prompt + crawl | ✅ |
| 179 ⭐ | Source-code RAG (LLM Q&A over JS bundle) | LangChain + repo | ✅ |
| 180 ⭐ | LLM-assisted parameter inference | GPT + arjun chain | ✅ |
| 181 ⭐ | Auto-generated phishing pretexts | LLM + LinkedIn OSINT | ✅ |
| 182 ⭐ | Image OCR + face-clustering OSINT | LLaVA, CLIP, Pimeyes | 👤 |
| 183 ⭐ | LLM exploit-PoC drafting from CVE | GPT + CVE-DB | 👤 |
| 184 ⭐ | AI-augmented Maltego graph expansion | LLM transforms | 👤 |

---

## Compliance / Standards Coverage

| Standard | Sections covered |
|---|---|
| **PTES Intelligence Gathering** | §1–§9 |
| **OWASP WSTG-INFO (4.2)** | §5 |
| **NIST SP 800-115 §4.2 Discovery** | §1, §2, §9 |
| **MITRE PRE-ATT&CK** | §1–§13 |
| **OSCP / OSWE methodology** | §1–§9 |
| **PCI DSS 11.3 (recon scope)** | §1, §2, §5, §9 |
| **NIS2 (EU) recon obligation** | §1, §8, §11 |
| **GDPR / DPDP recital (lawful basis)** | §4, §7, §11 |

---

## What VulnusLab Recon Module Has (per memory)

Per `project_v2_streaming_complete.md` (2026-05-23): **41 tools across 8 tier subdirs**, NDJSON streaming orchestrator, **96/100 industry-leading**.

Per `project_offline_ai_curation_recon.md` (2026-05-20): AI-curated wordlists shipped (3339 paths + 752 subs + 221 fingerprints + 270 buckets) across 4 scanners.

Per `project_session_2026-05-15_recon_complete.md`: 24 /api/recon/* endpoints + CVE matching via NVD + full PDF report end-to-end.

**Coverage to verify:** likely ~140/156 auto-able techniques = ~90% Full Industry Standard.

---

## Roadmap to 100% Full Industry Standard

| Phase | Scope | Tech adds | Effort |
|---|---|---|---|
| **Phase R-1** | Audit shipped scanners vs §1–§9 + close obvious gaps | ~5 scanners | 1 day |
| **Phase R-2** | Add modern API discovery (§5 #83–85 gRPC + WebSocket + SSE) | +3 scanners | 4 hours |
| **Phase R-3** | Add §6 cloud-asset modern (Actions runners + Lambda URLs + OIDC) | +3 scanners | 6 hours |
| **Phase R-4** | Add §7 identity-OSINT (Holehe + GHunt + LinkedIn) | +3 scanners | 4 hours |
| **Phase R-5** | Add §10 supply-chain (Actions secret leak + OAuth app abuse) | +2 scanners | 4 hours |
| **Phase R-6** | Add §11 stealer logs / ransomware sites | +2 scanners | 4 hours |
| **Phase R-7** | Add §13 AI/LLM-assisted (entire new section) | +5 scanners | 2 days |

**Result:** ~160 auto-able scanners = **100% Full Industry Standard** Recon SaaS.

---

## Top 10 — Highest-ROI Scanners to Add

| Rank | Tech # | Scanner | Why |
|---|---|---|---|
| 1 | #177–178 | `llm_wordlist_curator` + `ai_endpoint_guesser` | 30% more findings vs static lists |
| 2 | #46 | `subdomain_takeover_verifier` | CVE-class hit rate |
| 3 | #83–85 | `grpc_websocket_sse_discovery` | Modern APIs missed by legacy |
| 4 | #102 | `cloud_function_url_enum` | Serverless = top 2025 attack surface |
| 5 | #26 | `dns_rebinding_susceptibility` | Easy auto, rare in competitors |
| 6 | #116–117 | `holehe_audit` + `ghunt_google_audit` | Free identity-recon depth |
| 7 | #164 | `stealer_log_search` | Initial-access-broker visibility |
| 8 | #156 | `gha_secret_leak_scan` | High-value supply chain |
| 9 | #101 | `gha_self_hosted_runner_discovery` | CI/CD attack-surface map |
| 10 | #183 | `llm_cve_poc_drafter` | Closes recon → exploitation loop |

---

## Phase R-1 Quick-Win Scanners (Audit + Patch §1–§9)

| § | Tech # | Scanner to verify exists | Module path (proposed) |
|---|---|---|---|
| §1 | #14 | `cert_san_aggregator` | tools/recon/tier1_passive/ |
| §2 | #26 | `dns_rebinding_susceptibility` | tools/recon/tier2_dns/ |
| §5 | #83 | `grpc_reflection_discovery` | tools/recon/tier4_web/ |
| §5 | #84 | `websocket_endpoint_discovery` | tools/recon/tier4_web/ |
| §5 | #85 | `sse_endpoint_discovery` | tools/recon/tier4_web/ |
| §6 | #101 | `gha_runner_discovery` | tools/recon/tier5_cloud/ |
| §6 | #102 | `cloud_function_url_enum` | tools/recon/tier5_cloud/ |
| §7 | #116 | `holehe_email_audit` | tools/recon/tier7_email_people/ |
| §7 | #117 | `ghunt_google_audit` | tools/recon/tier7_email_people/ |
| §10 | #156 | `gha_secret_leak_scan` | tools/recon/tier8_code_intel/ |

---

## References

- **PTES Intelligence Gathering:** http://www.pentest-standard.org/index.php/Intelligence_Gathering
- **OWASP WSTG-INFO:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/
- **MITRE PRE-ATT&CK (TA0043):** https://attack.mitre.org/tactics/TA0043/
- **NIST SP 800-115:** https://csrc.nist.gov/publications/detail/sp/800-115/final
- **OSINT Framework:** https://osintframework.com/
- **Bellingcat OSINT toolkit:** https://www.bellingcat.com/category/resources/
- **ProjectDiscovery (subfinder/httpx/nuclei/katana):** https://github.com/projectdiscovery
- **Amass:** https://github.com/owasp-amass/amass
- **theHarvester:** https://github.com/laramies/theHarvester
- **Holehe:** https://github.com/megadose/holehe
- **GHunt:** https://github.com/mxrch/GHunt
- **Cloud_enum:** https://github.com/initstring/cloud_enum
- **SecurityTrails API:** https://securitytrails.com/corp/api
- **Shodan / Censys / InternetDB:** https://shodan.io / https://censys.io / https://internetdb.shodan.io
- **HIBP API:** https://haveibeenpwned.com/API/v3
