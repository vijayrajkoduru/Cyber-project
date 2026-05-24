# OSINT Module — VL-FOUNDRY Forge Checklist

**Started:** 2026-05-24
**Branch:** main (forge in main since this is the first cold-context forge — the framework itself is the gate)
**Audit target:** score >= 85 from `python scripts/score_module.py osint`

---

## Layer 1 — Module Role

**Customer question this module answers:**
*"What can a phisher or social engineer learn about my organization from public
sources without ever touching my infrastructure?"*

**PTES / NIST mapping:**
- PTES §4 — Intelligence Gathering > Open Source
- NIST SP 800-115 §4.2 — Information Gathering

**Why it exists (3 bullets):**
- Pentesters / threat actors start here, not with port scans — model the actual attack surface
- Customer's GDPR / data-minimization stance depends on what's actually leaked publicly
- A clean Recon scan tells you nothing about what's on Pastebin or in a recruiter's LinkedIn post

**What it isn't (3 bullets):**
- Not Recon — no DNS / port / subdomain probing of customer infrastructure (that's a different PTES phase)
- Not Vuln — no CVE matching or version detection
- Not active reconnaissance — every probe targets THIRD-PARTY sources (search engines, CT logs, public archives), NOT the customer

**Run ordering vs other modules:**
- Customer typically runs OSINT FIRST (before Recon) — informs DNS targets to probe in Recon
- OSINT findings feed `scan_state.json` keys: `osint.emails`, `osint.handles`, `osint.leaked_docs`
- Recon's `subdomains` and `cdn_origin` scanners can consume `osint.emails` for org-level enumeration

---

## Layer 2 — Tool Catalogue (12 scanners across 4 tiers)

### Tier 1 — Passive Domain Surface (3 scanners)

| Scanner | Role |
|---|---|
| `dnstwist` | Generate 7 transform classes (homoglyph/swap/add/omit/transpose/replace/TLD-swap) → DNS-resolve each → flag any resolving permutation as phishing infra candidate |
| `geoip` | IP → ISP/ASN/city/country/lat-lon/timezone via ip-api.com (free, no key) |
| `wayback_history` | Wayback Machine snapshot count + first/last seen dates + extracted URL patterns |

### Tier 2 — People & Identity (3 scanners)

| Scanner | Role |
|---|---|
| `harvester_emails` | Bing + DDG search for `"target.com" email` → regex-extract emails from result snippets |
| `crtsh_emails` | crt.sh CT log scrape → extract organization emails from cert subject fields |
| `social_handles` | HEAD-probe 12 social platforms (Twitter/X, GitHub, Reddit, LinkedIn, Instagram, YouTube, TikTok, Mastodon, Facebook, Pinterest, Twitch, Medium) for `target`-derived usernames |

### Tier 3 — Leaks & Code (3 scanners)

| Scanner | Role |
|---|---|
| `github_recon` | GitHub code search API (unauth, 10 req/min) for `target.com` mentions in public repos — flag any repo committing target's domain |
| `pastebin_search` | DDG-mediated `site:pastebin.com "target.com"` query → flag any indexed pastes |
| `breach_check` | HaveIBeenPwned breach API (no key needed for breach NAME lookup) — list any breaches mentioning target domain |

### Tier 4 — Metadata & Dorking (3 scanners)

| Scanner | Role |
|---|---|
| `document_metadata` | Crawl 3 known doc paths (`/sitemap.xml` → .pdf/.docx links) → extract author / creator-tool / timestamp via stdlib zip+xml parsing |
| `search_dorks` | Run 12 AI-curated Google-style dorks on DDG (filetype:pdf, intitle:"index of", inurl:admin, etc.) → flag any hit |
| `gravatar_check` | For any email found by harvester/crtsh, check gravatar.com profile existence via MD5 hash → identity surface |

**Total: 12 scanners (10 new + 2 existing)**

---

## Layer 3 — PDF Report

- Function: `generateOsintReport({target, allResults, date})` — ported from Webapp canon (`generatePDF` App.js:761)
- All 17 sections rendered; Tier Coverage matrix shows 4 tiers (Passive Domain / People / Leaks / Metadata)
- Per-tool sections rendered for 12 scanners
- Compliance Coverage: GDPR Art. 5, Art. 32 / ISO 27001 A.5.7 / NIST CSF ID.RA-2

---

## Layer 4 — Orchestrator

- `endpoints/osint_orchestrator.py` exists; extend `OSINT_TOOLS_BY_TIER` to 12 scanners
- POST `/api/osint/run_all` returns NDJSON stream
- POST `/api/osint/run_all_buffered` returns single JSON
- GET `/api/osint/run_all/tiers` returns the 4-tier discovery payload
- Concurrency cap: 6 (lower than Recon's 8 — third-party rate limits)
- Wall-clock per scanner: 30s (OSINT is mostly HTTP — no slow ports)

---

## Layer 5 — AI Curation

`tools/_payloads/osint/` (new directory):
- `email_patterns.py` — 60+ firstname/lastname/handle combination patterns
- `osint_dorks.py` — 50+ search dorks (filetype/inurl/intitle/site:)
- `social_handles.py` — 30+ username variation patterns (firstname, firstname.lastname, flastname, etc.)
- `social_platforms.py` — 12 platform URL templates

Generator: `tools/_gen/gen_osint_assets.py` (Anthropic SDK + CONFIGS list)

Refresh calendar: quarterly (90-day cadence — search engines change slowly)

---

## Layer 6 — Quality Bar (7-check DoD per scanner)

All 12 scanners must pass:
1. `safe_get()` precheck pattern (already provided by `tools._shared`)
2. `standard_response()` uniform shape
3. POSITIVE emit when clean
4. `severity` field on every finding
5. `remediation` field on every finding
6. `evidence_marker` field on every finding
7. Wall-clock cap via `timeout=` in safe_get / asyncio.wait_for

Parallel: scanners that make >1 HTTP call use `asyncio.gather` + `asyncio.Semaphore`.

---

## Layer 7 — Frontend

- `OSINT_PHASES` array in `src/App.js` — 12 entries matching orchestrator
- `OSINT_SECTION_HEADERS` dict — 4 tier headers with palette
- Module added to main nav under existing Recon/Vuln/Webapp tabs

---

## Layer 8 — Pricing

- Free tier: `geoip`, `dnstwist` (2 scanners)
- Starter ($29/mo): + `harvester_emails`, `crtsh_emails`, `social_handles`, `search_dorks` (6 total)
- Pro ($99/mo): all 12 scanners
- Enterprise ($299/mo): + Evidence Pack (CSV export of all findings + trend report)

---

## Layer 9 — Compliance

Primary control mapping:
- **GDPR Art. 5** (data minimization) — flags publicly-leaked PII attributable to org
- **GDPR Art. 32** (security of processing) — leaked employee emails = breach precursor
- **ISO 27001 A.5.7** (threat intelligence) — module satisfies the "external threat landscape monitoring" requirement
- **NIST CSF ID.RA-2** (cyber threat intelligence) — public-source intel feeds risk assessment
- **SOC 2 CC7.1** (security event monitoring) — leaked credentials surface

---

## Layer 20 — End-to-end gate

- `python scripts/e2e_test.py osint --target=vulnuslab.com --token=$VL_TOKEN` returns exit 0
- SLO: 120 seconds (matches Recon — third-party HTTP is the bottleneck)
- Already in `SLO_MAX_SECONDS` dict — no e2e_test.py edit needed

---

## Layer 21 — Pre-flight

- `python scripts/doctor.py` — green
- No new external CLI tools required (all scanners are pure-Python HTTP)
- No new Python deps required (uses existing httpx + stdlib regex/zip/xml)

---

## Final gate

- [ ] `python scripts/score_module.py osint` >= 85
- [ ] `python scripts/e2e_test.py osint` exit 0
- [ ] PDF renders all 17 sections (test scan against vulnuslab.com)
- [ ] Status matrix in VL-FOUNDRY.md updated
- [ ] All 12 scanners pushed
