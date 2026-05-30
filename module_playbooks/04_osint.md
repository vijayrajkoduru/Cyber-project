# Advanced OSINT & Threat Intel — Master Reference (`osint_ruff`)

**100% Full Industry Standard catalogue** — aligned with IntelTechniques methodology + Bellingcat OSINT framework + SANS SEC487 + MITRE PRE-ATT&CK + 2024–2026 industry additions (AI-assisted OSINT, identity recon, dark-web intel).

8 sections, 110 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Identity / People Intel | 18 | 16 | 2 |
| 2 | Domain / Infrastructure Intel | 14 | 14 | 0 |
| 3 | Social Media Intel (SOCMINT) | 18 | 16 | 2 |
| 4 | Threat Intel / Reputation | 14 | 13 | 1 |
| 5 | Breach / Dark Web Intel | 12 | 9 | 3 |
| 6 | Geo / Image Intel (GEOINT/IMINT) | 10 | 6 | 4 |
| 7 | Financial / Corporate Intel | 12 | 11 | 1 |
| 8 | AI/LLM-assisted OSINT ⭐ | 8 | 5 | 3 |
| **TOTAL** | | **106** | **90** | **16** |

---

## §1 — Identity / People Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Email harvesting | theHarvester, hunter.io | ✅ |
| 2 | HIBP breach lookup | HIBP API | ✅ |
| 3 | DeHashed credential search | DeHashed API | ✅ |
| 4 | Intelligence X paste search | IntelX API | ✅ |
| 5 | LeakCheck breach search | LeakCheck API | ✅ |
| 6 | Sherlock username pivot | Sherlock | ✅ |
| 7 ⭐ | Holehe forgot-password enum (60+ services) | Holehe | ✅ |
| 8 ⭐ | GHunt Google account intel | GHunt | ✅ |
| 9 | Phone number OSINT | PhoneInfoga | ✅ |
| 10 | LinkedIn employee enum | LinkedInt, ScrapedIn | ✅ |
| 11 | Reverse-image search (face) | PimEyes, Yandex | ✅ |
| 12 | TinEye / Google Lens | TinEye, manual | ✅ |
| 13 ⭐ | OSINT Industries aggregator | osint.industries | ✅ |
| 14 ⭐ | Spokeo / WhitePages / BeenVerified | manual / API | ✅ |
| 15 | Email pattern guess (hunter.io patterns) | hunter API | ✅ |
| 16 | Email validation (catchall + SMTP) | EmailValidator | ✅ |
| 17 | Manual creative pivot (employee names) | analyst | 👤 |
| 18 | Voice / face profile for vishing prep | manual | 👤 |

---

## §2 — Domain / Infrastructure Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 19 | WHOIS / RDAP lookup | whois, RDAP | ✅ |
| 20 | DomainTools historical WHOIS | DomainTools API | ✅ |
| 21 | SecurityTrails passive DNS | SecurityTrails API | ✅ |
| 22 | Farsight DNSDB | Farsight API | ✅ |
| 23 | Certificate Transparency log | crt.sh, censys | ✅ |
| 24 | Shodan host fingerprint | Shodan API | ✅ |
| 25 | Censys cert + host search | Censys API | ✅ |
| 26 ⭐ | InternetDB (free Shodan host info) | InternetDB API | ✅ |
| 27 | ASN + IP block lookup | bgp.he.net | ✅ |
| 28 | Reverse-IP (sibling domains) | hackertarget | ✅ |
| 29 | Wayback Machine timeline | web.archive.org CDX | ✅ |
| 30 | Common Crawl index | commoncrawl.org | ✅ |
| 31 | dnstwist / dnstwister typosquat | dnstwist | ✅ |
| 32 | favicon hash fingerprint (mmh3) | shodan favicon | ✅ |

---

## §3 — Social Media Intel (SOCMINT)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 33 | Twitter/X timeline mining | snscrape, Twitter API | ✅ |
| 34 | LinkedIn employee scrape | LinkedInt | ✅ |
| 35 | Facebook public posts | OSINT-SAN, manual | ✅ |
| 36 | Instagram public profile | osintgram | ✅ |
| 37 | TikTok scraper | tiktok-scraper | ✅ |
| 38 | YouTube channel + comment mine | youtube-comment-downloader | ✅ |
| 39 | Reddit user history | redditscraper, PullPush | ✅ |
| 40 | Discord channel scrape | Discord intel tools | ✅ |
| 41 | Telegram channel scrape | tg-channel-scraper | ✅ |
| 42 | Twitch user history | manual + API | ✅ |
| 43 | Bluesky firehose mine | bluesky API | ✅ |
| 44 | Mastodon federated mine | manual + APIs | ✅ |
| 45 | GitHub org/user activity | gh api + custom | ✅ |
| 46 | Pinterest / Quora / Stack pivot | manual | ✅ |
| 47 | Sherlock cross-platform username | Sherlock | ✅ |
| 48 ⭐ | Bellingcat OSINT toolkit | bellingcat-osint | ✅ |
| 49 | Manual creative sock-puppet build | analyst | 👤 |
| 50 | Manual real-name confirmation | analyst | 👤 |

---

## §4 — Threat Intel / Reputation

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 51 | VirusTotal domain/IP/URL/hash | VT API | ✅ |
| 52 | AbuseIPDB reputation | AbuseIPDB API | ✅ |
| 53 | AlienVault OTX indicators | OTX API | ✅ |
| 54 | URLhaus / MalwareBazaar | abuse.ch API | ✅ |
| 55 | ThreatFox IOC | abuse.ch ThreatFox | ✅ |
| 56 | MISP threat feed | MISP instance | ✅ |
| 57 | GreyNoise mass-scan attribution | GreyNoise API | ✅ |
| 58 | Mandiant Advantage threat actors | Mandiant API | ✅ |
| 59 | Recorded Future intel | RF API | ✅ |
| 60 | CrowdStrike Falcon Intel | CrowdStrike API | ✅ |
| 61 | ZoomEye host search | ZoomEye API | ✅ |
| 62 | FOFA / Quake (China) | FOFA API | ✅ |
| 63 ⭐ | LeakIX exposed asset feed | LeakIX API | ✅ |
| 64 | Manual attribution mapping | analyst | 👤 |

---

## §5 — Breach / Dark Web Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 65 | HIBP breach + paste API | HIBP API | ✅ |
| 66 | DeHashed cred search | DeHashed API | ✅ |
| 67 | Intelligence X paste/leak | IntelX API | ✅ |
| 68 | LeakIX | LeakIX API | ✅ |
| 69 ⭐ | Stealer log search (RedLine, Vidar, Stealc) | russianmarket monitors | ✅ |
| 70 ⭐ | Ransomware leak-site monitor | ransomwatch.org | ✅ |
| 71 | Hudson Rock free check | Hudson Rock API | ✅ |
| 72 | Snusbase paste search | Snusbase API | ✅ |
| 73 | Combolist scrape (legal-grey) | manual | 👤 |
| 74 | Tor hidden service crawl | OnionScan, Ahmia | 👤 |
| 75 | Telegram leak-channel monitor | manual + tg-archive | 👤 |
| 76 | Manual dark-web persona infiltration | analyst | 👤 |

---

## §6 — Geo / Image Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 77 | EXIF data extraction | exiftool | ✅ |
| 78 | Reverse-image search | TinEye, Yandex, Google Lens | ✅ |
| 79 ⭐ | PimEyes face search | PimEyes | ✅ |
| 80 | Google Maps / Street View pivot | manual | 👤 |
| 81 ⭐ | OpenStreetMap analysis | osmcal + manual | ✅ |
| 82 ⭐ | Mapillary street-level | mapillary API | ✅ |
| 83 | Geolocation by shadow / sun angle | SunCalc + manual | 👤 |
| 84 | Geolocation by language / signage | manual | 👤 |
| 85 ⭐ | CLIP / LLaVA image-to-text OSINT | LLaVA, CLIP | ✅ |
| 86 | Manual creative GEOINT chain | analyst | 👤 |

---

## §7 — Financial / Corporate Intel

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 87 | SEC EDGAR filings | SEC EDGAR API | ✅ |
| 88 | OpenCorporates registry | OpenCorporates API | ✅ |
| 89 | UK Companies House | Companies House API | ✅ |
| 90 | Indian MCA / Udyam registry | MCA API | ✅ |
| 91 | USPTO patent search | USPTO API | ✅ |
| 92 | EPO espacenet | EPO API | ✅ |
| 93 | TESS / EUIPO trademark | TESS / EUIPO | ✅ |
| 94 | Job posting scrape (tech-stack leak) | LinkedIn Jobs scrape | ✅ |
| 95 | Press release scrape | newsapi + custom | ✅ |
| 96 | Crunchbase company profile | Crunchbase API | ✅ |
| 97 | LinkedIn company connection count | LinkedInt | ✅ |
| 98 | Manual M&A / corporate timeline | analyst | 👤 |

---

## §8 — AI/LLM-assisted OSINT ⭐ NEW (2025+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 99 ⭐ | LLM-driven entity extraction | GPT-4o / Claude | ✅ |
| 100 ⭐ | LLM-assisted social-graph expansion | LLM + Maltego | ✅ |
| 101 ⭐ | LLM phishing pretext drafting | GPT + LinkedIn | ✅ |
| 102 ⭐ | LLM disinformation campaign detect | custom + LLM | ✅ |
| 103 ⭐ | Image-to-text OSINT (LLaVA / CLIP) | LLaVA | ✅ |
| 104 ⭐ | AI-assisted reverse-image clustering | CLIP embeddings | 👤 |
| 105 ⭐ | Deepfake detection (audio + video) | DeepFake-o-meter | 👤 |
| 106 ⭐ | LLM-driven sock-puppet persona gen | custom | 👤 |

---

## Compliance Mapping
- **PTES Intelligence Gathering** · **SANS SEC487** · **GDPR Art. 6 (lawful basis)** · **DPDP Act 2023** · **CCPA**

## VulnusLab OSINT Status
- Status: ✅ LIVE (11 working tools per memory)
- Tools: geoip, email_osint, recon_ng, spiderfoot, virustotal, abuseipdb, sherlock, hibp, dnstwist, googledorks, maltego
- Estimated coverage: ~25% of full standard (need to audit)

## Roadmap to 100%
1. Phase O-1: Audit existing 11 tools vs §1–§4 gaps
2. Phase O-2: Add §5 stealer-log + ransomware-site monitors (3 scanners)
3. Phase O-3: Add §6 image OSINT (LLaVA/CLIP) — 5 scanners
4. Phase O-4: Add §7 corporate intel (SEC EDGAR + OpenCorporates) — 4 scanners
5. Phase O-5: Add §8 AI/LLM-assisted OSINT (entire new section)

## References
- IntelTechniques: https://inteltechniques.com/
- Bellingcat: https://www.bellingcat.com/
- SANS SEC487: https://www.sans.org/cyber-security-courses/open-source-intelligence-gathering/
- Holehe: https://github.com/megadose/holehe
- GHunt: https://github.com/mxrch/GHunt
- Sherlock: https://github.com/sherlock-project/sherlock
- PhoneInfoga: https://github.com/sundowndev/phoneinfoga
- PimEyes: https://pimeyes.com/
- HIBP: https://haveibeenpwned.com/API/v3
