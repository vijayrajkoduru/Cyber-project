# VulnusLab Module Framework

Every VulnusLab module follows the same 3-layer structure. This document is
the canonical reference for *what each layer does, why it exists, and how to
describe it externally* (marketing copy, customer demos, sales decks).

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1 — MODULE        (the phase / the "why")            │
│  Layer 2 — TOOLS         (the scanners / the "how")         │
│  Layer 3 — REPORT        (the PDF / the "what they buy")    │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Module Role

**Definition:** the pentest phase this module covers and the question it
answers for the customer.

### Template

```
[ModuleName] — [pentest phase] — answers "[one-sentence customer question]"

Why it exists:
  • [reason 1 — usually compliance / methodology]
  • [reason 2 — usually customer pain]

What it isn't:
  • [out-of-scope thing 1]
  • [out-of-scope thing 2]

When customer runs it:
  • [order in pentest sequence]
  • [authentication requirement]
```

### Recon (filled in)

> **Recon — Information Gathering / OSINT phase — answers "what does the
> attacker see before they attack?"**
>
> **Why it exists:**
> - PTES + NIST SP 800-115 require Intelligence Gathering as Phase 1 of any pentest
> - Customers can't fix what they don't know they're exposing
>
> **What it isn't:**
> - Not vulnerability exploitation (no CVE firing) — that's Vuln module
> - Not webapp attack testing (no XSS/SQLi probes) — that's Webapp module
> - Not authenticated testing — purely external attack surface
>
> **When customer runs it:**
> - **First** of the 3 modules — cheapest, fastest, broadest
> - No authentication required (passive + light-active only)

### Vuln (to fill)

> **Vuln — Infrastructure Vulnerability Assessment phase — answers "what
> known CVEs and misconfigs are on the customer's hosts?"**
>
> **Why it exists:** matches Nessus / Qualys / Rapid7 InsightVM coverage.
> Required for PCI 11.2.x, SOC2 CC7.1, ISO A.8.8.
>
> **What it isn't:** not application-layer testing (that's Webapp).
>
> **When customer runs it:** after Recon, before Webapp. Needs the discovered
> open ports + service versions from Recon to be effective.

### Webapp (to fill)

> **Webapp — Web Application Pentest phase — answers "what OWASP-Top-10
> class vulnerabilities does the application have?"**
>
> **Why it exists:** matches Burp Pro / OWASP ZAP / Acunetix coverage.
> Required for PCI 6.5, ASVS Level 1+.
>
> **What it isn't:** not infrastructure scanning (that's Vuln).
>
> **When customer runs it:** after Recon (uses discovered subdomains +
> tech-stack fingerprint). Optionally authenticated for deeper coverage.

---

## Layer 2 — Tool Role

**Definition:** each scanner in the module answers ONE specific question.
Tools are described in a one-line format that scales (41 tools in Recon,
16 in Vuln, 60 in Webapp).

### Template

```
| Tool Name | One-line question it answers + canonical output |
```

### Recon (filled in — sample of 41)

| Tier | Tool | Role |
|---|---|---|
| 1 Identity | WHOIS Lookup | Registrar, age, expiry, status codes, abuse contact |
| 1 Identity | DNS Records | A/AAAA/MX/NS/TXT/CNAME/SOA — mail provider + SPF posture |
| 1 Identity | DNS Recon | Cross-resolver consistency + reverse DNS + DNSSEC chain |
| 2 Subdomains | Subdomain Discovery | Brute-force with 1,340 AI-curated prefixes |
| 2 Subdomains | Cert Transparency | crt.sh + certspotter — subdomains in TLS cert SANs |
| 2 Subdomains | Deep Subdomain (amass) | Passive aggregation across 4+ third-party sources |
| 3 OSINT | OSINT Harvesting | theHarvester — public search + breach databases |
| 3 OSINT | Shodan Lookup | Banners, tags, location, CVE list (API key required) |
| 3 OSINT | Free Shodan | /internetdb — ports + hostnames + tags (no key) |
| 4 Ports | Fast Port Scan | Top-46 TCP ports — confirms HTTP/HTTPS exposure |
| 4 Ports | Deep Port Scan | Top-1000 TCP ports |
| 4 Ports | Service Detection | Banner + version regex per open port |
| 4 Ports | OS Fingerprinting | TCP/IP stack signature inference |
| 4 Ports | Banner Grabbing | Raw banner capture |
| 5 Cloud | ASN / IP Ownership | BGP prefix, ASN org, country |
| 5 Cloud | Cloud Bucket Finder | 180 buckets × 7 providers permuted |
| 5 Cloud | Bucket Permissions | Public read/write check on discovered buckets |
| 5 Cloud | CDN Origin Discovery | Tries Cloudflare/Fastly origin bypass |
| 6 Threat | CVE Matching (NVD) | Live NVD lookup per detected tech version |
| 6 Threat | WAF / CDN Fingerprint | wafw00f + custom probes |
| 7 Content | Directory Enum (gobuster) | 3,339 AI paths — /admin, /.env, /.git, /backup |
| 7 Content | JS Endpoint Extractor | Regex fetch/axios/XHR URLs in JS bundles |
| 7 Content | Wayback Machine | archive.org snapshots |
| 7 Content | robots + sitemap | Disallow + sitemap + .well-known/ |
| 7 Content | BFS Crawler | Same-origin link graph depth 3 |
| 7 Content | Parameter Discovery | Hidden URL/form/JS-literal params |
| 7 Content | Favicon Fingerprint | MurmurHash3 → Shodan favicon match |
| 8 Posture | TLS Deep Audit | Protocols + ciphers + cert + HSTS + ALPN + POODLE/BEAST |
| 8 Posture | DNS Zone Transfer | AXFR test per authoritative NS |
| 8 Posture | Source Map Exposure | 19 standard .map paths |
| 8 Posture | API Docs Discovery | swagger/openapi/graphql/postman |
| 8 Posture | Admin Panel Exposure | 33 common admin paths |
| 8 Posture | JS Library CVE | Retire.js signature match |
| 8 Posture | Git Repo Exposure | /.git, /.svn, /.hg, /.bzr probes |
| 8 Posture | Breach Search | Have-I-Been-Pwned domain lookup |
| 8 Posture | GitHub Leaks | Repos mentioning domain + secret patterns |
| 8 Posture | GraphQL Introspection | /graphql introspection-allowed check |
| 8 Posture | Email Security | SPF/DMARC/DKIM/MTA-STS/TLS-RPT/CAA |
| 8 Posture | Search-Engine Dorks | 12 site: dorks for sensitive indexed content |
| 8 Posture | DNSSEC Validate | DNSKEY + DS chain verification |
| 8 Posture | WordPress wp-json Enum | /wp-json/wp/v2/users user enumeration |
| 8 Posture | Sub Takeover | DNS dangling-CNAME + 200 service signatures |

### How to describe new tools

Every tool description must answer:
1. **What does it probe?** (the input)
2. **What does it produce?** (the output)
3. **Why does the customer care?** (the value)

Bad: *"Runs wafw00f against the target"*
Good: *"WAF / CDN Fingerprint — identifies vendor (Cloudflare/Akamai/Fastly)
via active probes; tells customer whether they have edge protection"*

---

## Layer 3 — Report (PDF) Role

**Definition:** the artifact the customer actually pays for. Everything else
exists to feed this document.

### Why the PDF is the product

| Role | Why it matters |
|---|---|
| **Translation** | Raw scanner JSON → language a CISO / CFO / auditor acts on |
| **Evidence** | Proves what was tested, when, against what — SOC2/PCI/ISO auditable |
| **Prioritization** | Findings sorted by CVSS + severity → Monday-morning fix list |
| **Remediation** | Per-finding fix snippets (nginx config, headers, version upgrades) |
| **Compliance map** | Findings → PCI / SOC2 / ISO / HIPAA / GDPR / NIST / CIS controls |
| **Trust anchor** | Verified-by stamp + Report ID + content hash = tamper evidence |

### Canonical 9-block layout ("vulntemplate")

```
1. Cover               — target, date, classification, scope
2. Tools Used          — every scanner + finding count
3. Executive Summary   — risk score, severity bar, top-3 priorities
4. Findings Summary    — CRIT / HIGH / MED / LOW counters
5. OWASP / Compliance  — A01-A10 coverage + 8-framework mapping
6. Scan Coverage       — % phases completed + per-phase status
7. Per-Tool Findings   — one section per scanner (severity / CVSS / CWE /
                         OWASP / remediation / evidence_marker)
8. Verification Audit  — proves what was PROBED, not just FOUND
9. Appendix            — methodology + CVSS scale + references
```

### Rules for every PDF (the 7-check Definition of Done)

1. ✅ **Risk score** in executive summary (0-100, color-coded)
2. ✅ **Severity bar** showing distribution at a glance
3. ✅ **Per-finding CVSS + CWE + OWASP** — no findings without taxonomy
4. ✅ **Per-finding remediation** — every HIGH/CRIT has a fix snippet
5. ✅ **Per-finding evidence_marker** — what the scanner actually observed
6. ✅ **Verification audit** — proves negative tests too ("0 OK" rows)
7. ✅ **Report ID + content hash** — tamper-evidence + reproducibility

### What distinguishes VulnusLab PDFs

- **Per-scanner verification audit** — competitors only show findings;
  we show what was *probed*. Auditors actually want this.
- **9-block structure consistent across all 3 modules** — customer learns once.
- **AI-curated remediation** — fix snippets are copy-paste-ready, not generic.
- **No template-only matches** — every finding independently triggered and
  re-confirmed by the engine before emission.

---

## How to apply this framework to a new module

1. **Layer 1:** answer the customer question this module solves. Write it as
   a single sentence. Document why it exists, what it isn't, and when it runs.
2. **Layer 2:** list every scanner in a one-line table. Each row answers one
   specific question. Group by tier so customers can run partial scans.
3. **Layer 3:** every finding flows into the 9-block PDF template. Confirm
   the 7-check Definition of Done passes before shipping.

If any layer is incomplete, the module isn't ready for customers.

---

## Module status matrix (as of 2026-05-24)

| Module | Layer 1 (role) | Layer 2 (tools) | Layer 3 (PDF) | Production-ready |
|---|---|---|---|---|
| Recon | ✅ documented | ✅ 41/41 catalogued | ✅ 9-block live | **YES** — 96/100 |
| Vuln | ✅ documented | ✅ 16/16 catalogued | ✅ 9-block live | **YES** — 88/100 |
| Webapp | ✅ documented | ⚠️ 60/60 catalogued, 33/60 curated | ⚠️ 9-block partial | **MOSTLY** — 78/100 |

Score formula computed by `scripts/score_module.py`. Manual edits to this
table are advisory only — the script is the source of truth.

---

## Layer 4 — Orchestrator

**Definition:** how scanners run together. Without this, tools are just
isolated endpoints with no coordination.

**Required artifacts:**
- `endpoints/<module>_orchestrator.py`
- `<MODULE>_TOOLS_BY_TIER` dict mapping tier → list of `(name, route)` tuples
- POST `/api/<module>/run_all` returning NDJSON stream
- POST `/api/<module>/run_all_buffered` for non-streaming clients
- GET `/api/<module>/run_all/tiers` for discovery (frontend builds tier filter)

**Concurrency rules:**
- Default `concurrency=8-12` (max in-flight tool calls)
- Heartbeat every 15s (Cloudflare cuts at 100s TTFB)
- Per-tool timeout: 240s (orchestrator-side wall clock)
- Tier ordering: discovery first (populates `scan_state.json`), then deeper tiers

**State passing:** see Layer 10 (cross-module data contract).

---

## Layer 5 — Wordlists / AI Curation (THE MOAT)

**Definition:** offline AI-curated payload data. Build-time AI generates wordlists; runtime is fully offline.

**Required artifacts:**
- `tools/_payloads/<module>/` directory
- `_loader.py` with `load_json(name, fallback)` + `load_lines(name, fallback)`
- `tools/_gen/gen_<module>_assets.py` — Anthropic-API generator
- Each scanner has `_FALLBACK_*` const for when wordlist missing
- All wordlists committed to git (deploy travels with code)

**Refresh calendar:**
| Asset type | Cadence | Reason |
|---|---|---|
| `cve_match` / `tech_cve_map` | Monthly | CVE landscape moves fast |
| `default_creds` | Monthly | New vendor defaults / breaches |
| `service_banners` | Monthly | Banner formats change |
| `sqli` / `xss` / `cmd_injection` / `lfi` payloads | Quarterly | WAF bypass techniques evolve |
| `secrets_patterns` | Quarterly | New API key formats |
| `jwt_secrets` | Annually | Cracked-corpora stable |
| `exposed_files_paths` | Annually | Path conventions stable |

**Refresh cost:** ~$1–3 per batch via Anthropic API. Runtime cost: $0.

---

## Layer 6 — Quality bar (VL-FORGE 7-check Definition of Done)

**Definition:** the contract every scanner must satisfy before shipping.

```
1. precheck_target() reachability guard
   └─ Returns early with skipped_reason if target unreachable
2. vuln_response() / standard_response() uniform shape
   └─ Same JSON shape across all scanners in the module
3. Auto-emits POSITIVE finding when clean
   └─ "No issues detected" is a finding, not silence
4. Severity / CVSS / CWE / OWASP fields on every finding
   └─ wrap_finding() with all 4 dimensions
5. Remediation guidance per finding
   └─ Copy-paste-ready fix snippet (nginx config, header, etc.)
6. evidence_marker per finding
   └─ What the scanner OBSERVED (proves the finding isn't speculation)
7. Wall-clock cap + per-probe timeout
   └─ asyncio.wait_for(..., 60-90s) + per-request timeout 3-5s
```

**Enforced by:** `scripts/score_module.py` via AST inspection.

---

## Layer 7 — Frontend integration

**Definition:** how the customer triggers and visualizes scans.

**Required artifacts:**
- `<MODULE>_PHASES` array in `src/App.js` — mirrors orchestrator 1:1
- `<MODULE>_SECTION_HEADERS` dict — tier headers + colors
- Live scan-tile rendering (dot + glyph + name + badge + count + elapsed + Details)
- Per-finding section in PDF generator (`generate<Module>Report()`)

**Rule:** if `<MODULE>_TOOLS_BY_TIER` in orchestrator has 60 entries, `<MODULE>_PHASES` in App.js must have 60 entries. No orphans, no extras.

---

## Layer 8 — Pricing tier mapping

**Definition:** how monetization is gated. (Defer to Sell phase, but document upfront.)

**Default tier ladder:**
| Tier | Price | Scans/mo | Modules | Notes |
|---|---|---|---|---|
| Free | $0 | 3 | Recon only | Watermarked PDF |
| Starter | $29/mo | 50 | All 3 | 5 targets max |
| Pro | $149/mo | 500 | All 3 | Branded PDF + API |
| Enterprise | $999+/mo | unlimited | All + scheduled | SOC2 evidence pack |

**Per-scanner gating:** some scanners require Pro+ (e.g., `authenticated_scan`, deep brute-force).

---

## Layer 9 — Compliance certification mapping

**Definition:** which audit frameworks each module satisfies.

| Module | PCI-DSS | SOC2 | ISO 27001 | HIPAA | GDPR | NIST 800-53 | CIS v8 |
|---|---|---|---|---|---|---|---|
| Recon | n/a (recon) | CC7.1 | A.5.7 | n/a | n/a | RA-5 | 18.1 |
| Vuln | 11.2.x | CC7.1 | A.8.8 | 164.308(a)(1) | Art. 32 | RA-5, SI-2 | 7.6 |
| Webapp | 6.5 | CC8.1 | A.14.2 | 164.312(e) | Art. 32 | SA-11 | 16.10 |

PDF reports include this mapping per finding under the "Compliance Coverage" section.

---

## Layer 10 — Cross-module data contract

**Definition:** what state flows between modules. Without this, Recon's
discovery doesn't feed Vuln/Webapp.

**Schema** (written to `scan_state.json` by upstream modules):

```json
{
  "target": "vulnuslab.com",
  "scan_id": "VL-20260524-A1B2C3",
  "recon": {
    "subdomains": ["app.vulnuslab.com", "www.vulnuslab.com"],
    "resolved_ips": ["18.208.88.157", "98.84.224.111"],
    "open_ports": [80, 443],
    "tech_stack": ["nginx 1.28.0", "cloudflare"],
    "behind_cdn": true,
    "tls_protocols": ["TLSv1.2", "TLSv1.3"]
  },
  "vuln": {
    "detected_cves": ["CVE-2024-6387"],
    "service_versions": {"22/tcp": "OpenSSH 9.6p1"}
  }
}
```

**Consumers:**
- Vuln reads `recon.open_ports` → only probes those, skips closed ports
- Webapp reads `recon.subdomains` → scans all discovered subs, not just apex
- Webapp reads `recon.tech_stack` → only runs WordPress scanners if WP detected

---

## Layer 11 — Failure modes (triage runbook)

**Layer 5 broken** — wordlist not loading
- Symptom: PDF shows "AI-curated (10 entries)" instead of "AI-curated (1340 entries)"
- Triage: `docker compose exec backend python -c "from tools._payloads.X import Y; print(len(Y))"`
- Fix: verify file in container; if missing, copy from /tmp/vl_payloads/ + rebuild

**Layer 6 broken** — scanner missing 7-check
- Symptom: `python scripts/score_module.py <module>` returns < 85
- Triage: read scorer output — names which scanner fails which check
- Fix: edit scanner to add missing precheck/timeout/POSITIVE emit

**Layer 4 broken** — orchestrator out of sync
- Symptom: scan PDF has 32 scanners but disk has 60
- Triage: `python -c "from endpoints.X_orchestrator import _all_tools; print(len(_all_tools()))"`
- Fix: add missing scanners to `<MODULE>_TOOLS_BY_TIER`

**Layer 7 broken** — frontend missing tile
- Symptom: scan runs in backend but no tile in UI
- Triage: `grep '"<scanner_name>"' src/App.js` — should appear in PHASES
- Fix: add entry to PHASES array

**Layer 3 broken** — PDF section missing
- Symptom: scan completes but section X is blank in PDF
- Triage: search for scanner tool name in `generate<Module>Report()` function
- Fix: add per-tool findings table

---

## Layer 12 — Cost model

**Per-module monthly cost** (assuming 1,000 scans/month):

| Component | Recon | Vuln | Webapp | Notes |
|---|---|---|---|---|
| AI curation refresh | $5/mo | $3/mo | $8/mo | Anthropic API (monthly refresh tier) |
| Compute (CPU/RAM share) | $3 | $4 | $5 | VPS proportional |
| NVD / Shodan API hits | $2 | $5 | $2 | Free tiers usually sufficient |
| Storage (PDF + cache) | $1 | $1 | $1 | S3-class storage |
| **Total per 1k scans** | **$11** | **$13** | **$16** | **~$40/mo combined** |

**Per-scan cost** (1,000 scans): $0.01-0.02 each. Gross margin at Pro pricing ($149/mo for 500 scans): ~95%.

---

## Module lifecycle

```
   FORGE → CURATE → SHIP → MAINTAIN → RETIRE
     │       │       │        │          │
     │       │       │        │          └─ Replaced or absorbed
     │       │       │        │             into another module
     │       │       │        │
     │       │       │        └─ Quarterly AI curation refresh
     │       │       │           Monthly score audit via scripts/score_module.py
     │       │       │
     │       │       └─ Score ≥ 85, all 9 layers GREEN
     │       │
     │       └─ Run gen_<module>_assets.py + handcraft refusals
     │
     └─ "Forge X" — apply this framework end-to-end
```

---

## How to validate the framework itself

The acid test: **Forge a brand-new module using only this document.** If you
can go from zero to ≥85/100 without me improvising new layers, the framework
is real. If you can't, the framework needs another revision.

Validate after each new module forge:
```bash
python scripts/score_module.py <new_module>
```

If consistently ≥ 85 → framework is solid.
If routinely < 85 → add the missing layer or detail.

---

## Definition of a Module (when to forge vs. extend)

Before saying "Forge X" — verify X actually merits a new module:

| Test | If YES → new module | If NO → extend existing |
|---|---|---|
| Does it have its own pentest **phase** (PTES / NIST 800-115)? | ✅ | ❌ extend |
| Would it have **≥ 10 distinct scanners**? | ✅ | ❌ extend |
| Does it produce a **standalone PDF** customers want? | ✅ | ❌ extend |
| Does it have its **own NDJSON orchestrator** flow? | ✅ | ❌ extend |
| Is there an **industry-recognized name** for this category? | ✅ | ❌ extend |

If 3+ "no" → it's a sub-feature, not a module. Add as new scanners to existing.

**Examples:**
- "Add Kerberos enum" → extend Vuln (not new module)
- "Cloud security (AWS/GCP/Azure config audit)" → NEW module (5/5 yes)
- "Mobile app pentest (APK + IPA)" → NEW module (5/5 yes)
- "Better SQLi payloads" → extend Webapp's sqli scanner

---

## Layer 11 — Naming conventions

Validated by `tools/_framework/naming.py`, enforced by `scripts/score_module.py`.

**Module names:** lowercase, ≤ 12 chars, in allowed set (recon/vuln/webapp/osint/password/cloud/mobile/api/network/exploit/bof). Must be added to `_VALID_MODULES` first.

**Scanner names:** `^[a-z][a-z0-9_]{2,40}$` — lowercase + underscores + digits only.

**Banned suffixes** (cause duplicates): `_detection`, `_detector`, `_scan`, `_check`, `_test`, `_v2`, `_new`, `_old`, `_legacy`, `_alt`.

**Banned pluralization confusion** — never ship two scanners differing only by plural/singular:
- ❌ `nosql` + `nosqli`  → pick one
- ❌ `force_browse` + `forced_browsing`  → pick one
- ❌ `idor` + `idor_detector`  → drop the `_detector`

Pre-commit linter: `python -m tools._framework.naming <module>` exits 1 on violations.

---

## Layer 13 — Observability

Defined in `tools/_framework/observability.py`. Every scanner records each scan attempt:

```python
from tools._framework.observability import record_scan
record_scan(module="recon", scanner="wayback", target="example.com",
            status="ok", duration_s=4.2, findings_count=3)
```

**SLO targets:**

| Module | SLO |
|---|---|
| Recon | ≥ 95% scans < 30s; ≥ 90% within-expected findings range |
| Vuln | ≥ 90% scans < 60s |
| Webapp | ≥ 85% scans < 90s |

**Health dashboard:** `python -c "from tools._framework.observability import health_summary; print(health_summary('webapp', 7))"` — per-scanner ok/skipped/failed % over 7 days.

**Degraded alert:** `alert_degraded(threshold_pct=80)` returns scanners below 80% success. Run as nightly cron → Slack webhook.

---

## Layer 14 — Deprecation process

When a scanner becomes obsolete:

1. Mark `_DEPRECATED = True` in scanner module
2. Soft-disable — remove from orchestrator `_TOOLS_BY_TIER`
3. Notify in release notes: "X deprecated, use Y instead"
4. Wait 60 days — Pro/Enterprise customers update integrations
5. Hard delete — `rm` + remove from App.js PHASES + update VL-FOUNDRY.md status matrix

Old reports referencing deleted scanners still render (frozen data).

---

## Layer 15 — Backwards-compatibility contract

**Stable (don't change without 90-day notice):**
- API routes: `/api/<module>/<scanner>`
- Scanner names in NDJSON output
- JSON finding shape (severity/cvss/cwe/owasp/remediation/evidence_marker keys)
- PDF Report ID format (`VL-YYYYMMDD-XXXXXX`)

**Internal (change anytime):**
- `_FALLBACK_*` consts, internal regex
- Wordlist file names + counts (refresh freely)
- Per-scanner implementation
- Tier names + groupings

Breaking-change procedure: add new version alongside (`/v2`), 90-day deprecation, then remove.

---

## Layer 16 — Customer feedback loop

Every PDF has a final-page CTA → `app.vulnuslab.com/feedback/<report_id>` (5-star rating + free-text). Captured to `feedback.jsonl` for monthly review. Scanners with low remediation-clarity get prioritized for AI-curation refresh.

---

## Layer 17 — Abuse prevention

- **Domain ownership verification** — DNS TXT record required for Free tier
- **Rate limiting** — 1 concurrent scan / Free, 3 / Starter, 10 / Pro
- **Banned targets** — google.com, microsoft.com, government domains, .gov, .mil
- **Scan velocity** — > 100 scans/hour → auto-suspend pending review

Implementation in `tools/_shared/abuse.py` (TODO post first paid customer).

---

## Layer 18 — A/B testing scanner improvements

When updating a scanner with new AI-curated payloads:
1. Branch + deploy to 10% of users (`User.flags.experiment_pool`)
2. Measure 1 week: hit rate, FP rate, duration delta
3. Promote if hit-rate ≥ +5% AND FP rate < +2% AND duration within SLO
4. Revert if hit-rate flat or FP rate up ≥ +5%

Tracked in `experiments.jsonl`.

---

## Layer 19 — Model version contract

Today: AI curation uses `claude-sonnet-4-6`.

When Claude updates (5.x etc.):
1. Re-gen all wordlists with new model on a branch
2. Diff sizes + category coverage
3. Test scan known-vuln target with both
4. Promote new wordlists if hit-rate improves OR same hit-rate with smaller list

Track model version per wordlist in its docstring:
```python
"""sqli_payloads — generated 2026-05-24 by claude-sonnet-4-6."""
```

---

## Companion documents

- `VL-FOUNDRY-CHECKLIST.md` — per-forge shipping checklist (copy + tick)
- `VL-FOUNDRY-AUDIT-AGENT.md` — agent prompts for per-layer verification
- `VL-FOUNDRY-PRICING.md` — Layer 8 concrete tier→scanner mapping
- `VL-FOUNDRY-COMPLIANCE.md` — Layer 9 finding→control mapping
- `scripts/score_module.py` — objective scorer
- `tools/_framework/scan_state.py` — Layer 10 schema enforcer
- `tools/_framework/observability.py` — Layer 13 health tracker
- `tools/_framework/naming.py` — Layer 11 naming validator
