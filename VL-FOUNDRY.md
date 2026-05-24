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

## Execution sequences (which layer runs when)

The 20 layers below are a **catalog**, not a runtime order. Three distinct
sequences fire at different times:

### Sequence A — Forge order (build-time, one-shot per module)

Strict order. Each layer's output feeds the next. Audit-agent fires after
EACH layer commits, not just at the end.

```
   ┌────────────────────────────┐
   │ Layer 21 doctor.py         │   PRE-FLIGHT
   │ (deps + CLIs + wordlists)  │   (lab must be current)
   └──────────────┬─────────────┘
                  ▼
   ┌────────────────────────────┐
   │ Layer 1  Module Role       │   DESIGN
   │ Layer 2  Tool Catalogue    │   (what)
   │ Layer 3  Report layout     │
   └──────────────┬─────────────┘
                  ▼
   ┌────────────────────────────┐
   │ Layer 4  Orchestrator      │
   │ Layer 5  AI Wordlists      │   BUILD
   │ Layer 6  Quality bar 7/7   │   (code)
   │ Layer 6b VL-TURBO parallel │
   └──────────────┬─────────────┘
                  ▼
   ┌────────────────────────────┐
   │ Layer 7  Frontend wiring   │   WRAP
   │ Layer 8  Pricing tier      │   (ship)
   │ Layer 9  Compliance map    │
   └──────────────┬─────────────┘
                  ▼
   ┌────────────────────────────┐
   │ Layer 20 E2E verify        │   GATE
   └────────────────────────────┘

Cross-cutting (apply at every layer — no fixed slot):
  Layer 10  scan_state schema
  Layer 11  naming validator
  Layer 12  cost model
  Layer 13  observability
  Layer 14-19  lifecycle policies (deprecation, A/B, model version, etc.)
  Layer 21  tooling freshness (weekly cron + pre-forge)
```

### Sequence B — Runtime order (every customer scan)

```
  1. Frontend POSTs target           (Layer 7)
  2. Orchestrator selects tier       (Layer 4)
  3. Precheck target reachable       (Layer 6 check #1)
  4. Load AI-curated wordlists       (Layer 5)
  5. Run scanners in parallel        (Layer 6b)
  6. Each scanner emits findings     (Layer 6 checks #2-6)
  7. Validate finding shape          (finding_schema.py)
  8. Stream NDJSON to client         (Layer 4)
  9. Frontend renders tiles          (Layer 7)
 10. Generate PDF                    (Layer 3)
 11. Log observability               (Layer 13)
```

### Sequence C — Verification order (after every change)

```
  1. pre_commit_score.py   →  blocks bad commits
  2. score_module.py       →  must be >= 85
  3. e2e_test.py           →  6 gates must all green
  4. audit-agent           →  cold-context double-check
```

### Quick lookup — which runs first?

| Situation | First thing that runs |
|---|---|
| Building a NEW module | Layer 1 (define the role) |
| Customer hits Scan | Frontend POST → orchestrator (7→4) |
| Committing scanner code | `scripts/pre_commit_score.py` (auto) |
| Shipping the module | `scripts/e2e_test.py` must exit 0 |

The framework knows the order via three sources of truth:
- `VL-FOUNDRY-CHECKLIST.md` — forge order (top to bottom)
- `endpoints/<module>_orchestrator.py` — runtime order (tier dict order)
- `VL-FOUNDRY-AUDIT-AGENT.md` — verify order (per-layer gates)

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

### Canonical PDF = the Webapp PDF (`generatePDF` in `src/App.js:761`)

The **Webapp module's PDF is the canonical VL-FOUNDRY report**. Every other
module's PDF must converge to this exact structure. The function
[`generatePDF`](src/App.js#L761) is the source of truth — when this doc and
the function disagree, the function wins, and this doc must be updated.

Why Webapp is the canon (not an abstract spec):
- It's the most-shipped report (every paid customer who runs an app scan)
- It has the deepest auditor feedback (OWASP grade + 8-framework compliance)
- It has every component the other modules need; the others are subsets

### The 17-section Webapp PDF layout

Section numbering matches the order they appear in [`generatePDF`](src/App.js#L761):

```
═════════════ COVER ═════════════════════════════════════════════
 1. Cover page          black header + logo + "PENETRATION TEST REPORT"
 2. Info table          Target / Date / Classification(CONFIDENTIAL badge) /
                        Authenticated yes-no / Prepared By
 3. Trust statement     "[VERIFIED] VULNUSLAB — every finding independently
                        triggered and re-confirmed" (blue accent box)
 4. Key Risk Headline   Single color-coded box (red/amber/yellow/green) with
                        severity tag + count + SLA ("patch within 24h")

══════════ EXECUTIVE SUMMARY ════════════════════════════════════
 5. Executive Summary   Severity × Count × SLA × Recommendation table
 6. OWASP Top 10 Grade  Letter grade A-F + per-category pass/fail row
 7. Compliance Coverage 8 frameworks (PCI / SOC2 / ISO / HIPAA / GDPR /
                        NIST 800-53 / NIST CSF / CIS) mapped to findings
 8. Remediation Diff    Fixed / Persisting / Novel vs previous scan

══════════ RISK PROFILE ═════════════════════════════════════════
 9. Risk Score Bar      0-100 numeric + colored progress bar + label
10. Severity Breakdown  Horizontal stacked bar per severity tier
11. Tier Coverage       Per-tier (Discovery/Recon/Injection/Auth/File/
                        Network/Access/Framework) coverage matrix

══════════ FINDINGS ═════════════════════════════════════════════
12. Per-Tool Sections   One section per scanner: Directory enum / Web
                        fuzz / Tech / SQLi / WAF / CMS / SSL/TLS / CORS /
                        Cookies / XSS / Subdomains / DNS / + extended set
13. Detailed Findings   Per-finding card: severity badge, CVSS, CWE, OWASP,
                        evidence (Courier font), Fix snippet (green accent),
                        References
14. Recommendations     Dynamic action list synthesized from findings

══════════ AUDIT TRAIL ══════════════════════════════════════════
15. Verification Audit  "What each scanner PROBED for" — shows depth
                        without leaking payloads
16. Appendix            Methodology · Severity scale · Tools used · References

══════════ EVERY PAGE ═══════════════════════════════════════════
17. Border + Footer     Blue rectangle border · Watermark · Report ID +
                        Content Hash centered in footer · CONFIDENTIAL tag
```

### The 7-check Definition of Done (per-PDF gate)

A module's PDF ships only when ALL 7 are present:

1. ✅ **Risk score (0-100)** in executive summary, color-coded
2. ✅ **Stacked severity bar** showing distribution at a glance
3. ✅ **Per-finding CVSS + CWE + OWASP** — no findings without taxonomy
4. ✅ **Per-finding remediation** — every HIGH/CRIT has a fix snippet
5. ✅ **Per-finding evidence_marker** — what the scanner actually observed
6. ✅ **Verification audit** — proves negative tests too ("0 OK" rows)
7. ✅ **Report ID + content hash** — tamper-evidence + reproducibility

### Current module convergence (2026-05-24)

| Block | Webapp (canon) | Vuln | Recon |
|---|---|---|---|
| 1. Cover | ✅ | ✅ | ✅ |
| 2. Info table | ✅ | ✅ | ✅ |
| 3. Trust statement | ✅ | ✅ | ✅ |
| 4. Key Risk Headline | ✅ | ✅ | ❌ |
| 5. Executive Summary | ✅ | ✅ | ⚠️ partial |
| 6. OWASP Top 10 Grade | ✅ | ✅ | ✅ |
| 7. Compliance Coverage | ✅ | ✅ | ❌ |
| 8. Remediation Diff | ✅ | ⚠️ | ❌ |
| 9. Risk Score Bar | ✅ | ✅ | ❌ |
| 10. Severity Breakdown | ✅ | ✅ | ⚠️ |
| 11. Tier Coverage | ✅ | ⚠️ | ✅ (Phases) |
| 12. Per-Tool Sections | ✅ | ✅ | ✅ (24 tools) |
| 13. Detailed Findings | ✅ | ✅ | ✅ |
| 14. Recommendations | ✅ | ✅ | ⚠️ |
| 15. Verification Audit | ✅ | ✅ | ✅ |
| 16. Appendix | ✅ | ✅ | ✅ |
| 17. Report ID + Hash | ✅ | ✅ | ❌ |

**Recon gap:** 4 missing + 3 partial. Retrofit by porting blocks 4, 7, 8, 9, 17
from [`generatePDF`](src/App.js#L761) into [`generateReconReport`](src/App.js#L7388).

### What distinguishes VulnusLab PDFs

- **Per-scanner verification audit** — competitors only show findings;
  we show what was *probed*. Auditors actually want this.
- **One canonical structure across all 3 modules** — customer learns once.
- **AI-curated remediation** — fix snippets are copy-paste-ready, not generic.
- **No template-only matches** — every finding independently triggered and
  re-confirmed by the engine before emission.
- **Tamper-evident** — Report ID (deterministic) + content hash in footer.

---

## How to apply this framework to a new module

1. **Layer 1:** answer the customer question this module solves. Write it as
   a single sentence. Document why it exists, what it isn't, and when it runs.
2. **Layer 2:** list every scanner in a one-line table. Each row answers one
   specific question. Group by tier so customers can run partial scans.
3. **Layer 3:** every finding flows into the **17-section Webapp PDF layout**
   (canon: `generatePDF` in `src/App.js:761`). Confirm the 7-check Definition
   of Done passes before shipping.

If any layer is incomplete, the module isn't ready for customers.

---

## Named Processes (the verbs of VL-FOUNDRY)

VL-FOUNDRY defines WHAT a module must contain (the 19 layers).
**Named Processes define HOW to build, refresh, and ship those parts.**

Every named process has:
- a trigger phrase (what you say to invoke it)
- an output (the artifact it produces)
- a step count (how many discrete actions)
- an approximate time + cost

When you write a commit message that says "Apply VL-TURBO to scanner X",
the process is unambiguous — everyone (you, agents, future devs) knows
exactly what was done.

---

### VL-FORGE — build ONE scanner

**Trigger:** `"Forge <scanner_name> for <module>"`

**Output:** `tools/<module>/<scanner>.py` that passes the Layer 6 7-check Definition of Done.

**Steps (7):**
1. Add scanner name to module's tier in `<MODULE>_TOOLS_BY_TIER` (Layer 4)
2. Create `tools/<module>/<scanner>.py` skeleton (FastAPI router + register)
3. Add `precheck_target()` reachability guard
4. Implement scan logic, emitting `wrap_finding()` for every finding (severity / CVSS / CWE / OWASP / remediation / evidence_marker)
5. Wrap output in `standard_response()` or `vuln_response()` for uniform shape
6. Emit POSITIVE finding when target is clean
7. Set wall-clock cap (60-90s) + per-probe timeout (3-5s)

**Verification:** `python scripts/score_module.py <module> --verbose` — scanner must show ≥ 5/7 checks passing in L6 Quality Bar.

**Time:** ~15 min per scanner.

**Pre-existing memory:** see `feedback_self_verify_before_show.md` — the
7-check pattern was codified after early FP/skip bugs.

---

### VL-TURBO — parallelize ONE scanner

**Trigger:** `"Apply VL-TURBO to <scanner>"`

**Output:** same scanner, refactored from sequential probes to async-parallel.

**Steps (6):**
1. Identify sequential pattern (nested `for` loops issuing requests)
2. Add `asyncio.Semaphore(N)` cap (N = 15-30 depending on probe weight)
3. Convert request loop to `asyncio.gather(*tasks)` with `asyncio.to_thread` if scanner uses sync `requests`
4. Lower per-probe timeout (8s → 3-5s)
5. Wrap full gather in `asyncio.wait_for(..., wall_clock_cap)` (60-90s)
6. Test against vulnuslab.com — confirm scan time drops by ≥ 3×

**Verification:** scorer's L6 parallel pct goes up. Scan duration drops.

**Time:** ~10 min per scanner.

**Pre-existing memory:** `project_vl_turbo_process.md` codified this after
Vuln scanners started hitting 240s wall-clock timeouts.

---

### VL-CURATOR — refresh AI wordlists for a module

**Trigger:** `"Refresh AI curation for <module>"` or `"Curate <asset> for <module>"`

**Output:** `tools/_payloads/<module>/<asset>.py` (or .json) with newer AI-generated content.

**Steps (5):**
1. Ensure `tools/_gen/gen_<module>_assets.py` has CONFIGS entry for the asset
2. Set `ANTHROPIC_API_KEY` env var
3. Run `python tools/_gen/gen_<module>_assets.py <asset>` — outputs to `/tmp/vl_payloads/`
4. Review the generated file (`/tmp/vl_payloads/<asset>.py`)
5. Move into place + commit:
   `cp /tmp/vl_payloads/*.py tools/_payloads/<module>/`

**Cost:** $1-3 per asset in Anthropic API tokens (build-time only — zero scan-time cost).

**Time:** ~5 min per asset, ~30 min for full module refresh.

**Refresh calendar** (from Layer 5):
- Monthly: `cve_match`, `default_creds`, `service_banners`
- Quarterly: `sqli`, `xss`, `cmd_injection`, `lfi`, `ssrf` payloads
- Annually: `jwt_secrets`, `exposed_files_paths`, `cms_fingerprints`

**Safety refusals:** Claude sometimes refuses dual-use prompts (credential brute, OAuth bypass, deserialization gadgets). When that happens, handcraft the wordlist instead — same shape, same fallback discipline.

---

### vulntemplate — render findings into the 9-block PDF

**Trigger:** `"Apply vulntemplate to <module>"`

**Output:** `generate<Module>Report()` function in `src/App.js` that produces the canonical 9-block PDF.

**Steps (9 — one per block):**
1. Cover block — target, date, classification, scope
2. Tools Used table — every scanner + finding count
3. Executive Summary — risk score (0-100) + severity bar + top-3 priorities
4. Findings Summary — CRITICAL / HIGH / MEDIUM / LOW counters
5. OWASP + Compliance Coverage (8 frameworks per `VL-FOUNDRY-COMPLIANCE.md`)
6. Scan Coverage table — % phases completed + per-phase status
7. Per-Tool Findings — one section per scanner with severity / CVSS / CWE / OWASP / remediation / evidence_marker
8. Verification Audit — what was probed (proves negative tests)
9. Appendix — methodology, CVSS scale, references

**7-check Definition of Done** for the PDF itself (mirrors Layer 6 for scanners):
- Risk score 0-100 in exec summary
- Severity bar (stacked horizontal)
- Per-finding CVSS + CWE + OWASP fields
- Per-finding remediation
- Per-finding evidence_marker
- Verification audit table
- Report ID + content hash

**Time:** ~30 min per module.

---

### How named processes interact

```
   ┌──────────────────────────────────────────────────────────────┐
   │   FORGE  →  TURBO  →  CURATOR  →  vulntemplate  →  SHIP     │
   └──────────────────────────────────────────────────────────────┘
        │         │           │              │             │
   build one  make it fast  feed it AI    render PDF   passes scorer
   scanner                 wordlists                   ≥ 85/100
```

Inside a single module forge (e.g., "Forge OSINT"):
1. Run **VL-FORGE** once per scanner (~15 min × 10-15 scanners = 2-4 hr)
2. Run **VL-CURATOR** once per scanner needing curation (~5 min × N)
3. Run **VL-TURBO** on scanners with sequential network loops
4. Run **vulntemplate** once for the module's PDF generator
5. Run scorer → if ≥ 85 → SHIP

---

### Process discovery (for agents / new devs)

If a future Claude session — or audit agent, or new dev — reads a commit
message that says `"Apply VL-TURBO to webapp/ldap_injection"`, they can:
1. Look up VL-TURBO in this section
2. Read the 6-step process
3. Know exactly what change was made and how to verify it

This is the difference between a *codebase with conventions* and a
*codebase with documented contracts*. Named processes are contracts.

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

## Layer 20 — End-to-end verification

Per-scanner unit checks (Layer 6) and the scorer (Layer 4–7) verify pieces
in isolation. They do NOT catch:

- Orchestrator drops a scanner mid-stream
- NDJSON corruption from a proxy (Cloudflare, nginx, gzip)
- Frontend can't parse a new finding shape
- PDF generator silently skips a section
- CORS / auth misconfig blocks the API
- Cloudflare 100s TTFB cuts the stream before payload arrives

Layer 20 closes the loop with a **full-chain test**: target in → NDJSON out
→ PDF rendered. One script, one exit code, CI-friendly.

**Artifact:** `scripts/e2e_test.py`

**Run:**
```bash
python scripts/e2e_test.py <module> [--target=<host>] [--api=<base_url>]
```

**Six verification gates (in order, fail-fast):**

1. **API reachable** — `GET /health` returns 200 within 5s
2. **POST returns 200** — `POST /api/<module>/run_all` with `{target, concurrency:8}` returns 200
3. **SLO check** — elapsed ≤ module SLO (Recon ≤ 120s, Vuln ≤ 300s, Webapp ≤ 90s, OSINT ≤ 120s)
4. **NDJSON record count sanity** — between 1 and 200 records (catches "empty stream" and "runaway")
5. **Each record has recognizable shape** — has at least one of `tool / target / findings / scanner / error`
6. **Orchestrator dispatched ≥ 70% of expected scanners** — catches silent scanner drops

**Output:** structured pass/warn/fail report + exit code (0 = pass, 1 = fail).

**When to run:**
- After every module forge — required for the Final Gate (see VL-FOUNDRY-AUDIT-AGENT.md)
- After ANY change to: `endpoints/<module>_orchestrator.py`, `src/App.js` finding-shape, PDF generator, Cloudflare/nginx config
- In CI before merging to main (`exit 1` fails the build)

**SLO source of truth:** `SLO_MAX_SECONDS` dict in `scripts/e2e_test.py`. Updates to module SLOs MUST update this dict + VL-FOUNDRY-AUDIT-AGENT.md Final Gate.

---

## Layer 21 — Tooling & dependency freshness

Scanners depend on three layers of tooling that **drift out of date** if no
process owns them:

| Tier | Examples | How it drifts |
|---|---|---|
| **Python packages** | `httpx`, `dnspython`, `anthropic`, `cryptography` | New CVE in a dep; new feature we want |
| **External CLI tools** | `nmap`, `nuclei`, `amass`, `sublist3r`, `whatweb` | Vendor releases new version with new probes |
| **Tool templates / signature DBs** | `nuclei-templates/`, JS lib signatures, CVE feeds | Daily/weekly upstream updates |

Layer 21 makes drift **detectable** and **fixable** in one command. It does
NOT auto-update in production — surprise upgrades break scans. It REPORTS,
then the operator runs the install.

**Artifact:** `scripts/doctor.py`

**Run:**
```bash
python scripts/doctor.py              # check only — list outdated / missing
python scripts/doctor.py --install    # install missing Python deps
python scripts/doctor.py --update     # upgrade outdated (pinned only)
python scripts/doctor.py --json       # CI-friendly machine output
```

**Five health checks (in order):**

1. **Python deps installed** — every package in `requirements.txt` resolves
2. **Python deps current** — `pip list --outdated` against pinned versions
3. **External CLI tools on PATH** — `which nmap / nuclei / amass / ...` returns a path
4. **External CLI tools current** — `<tool> --version` parsed and compared against `tools/_framework/tool_versions.json`
5. **Wordlist / template freshness** — mtime of each AI-curated wordlist vs the refresh calendar (Layer 5)

**Exit codes:**
- `0` — all green
- `1` — something missing (blocks CI)
- `2` — something outdated (warning, doesn't block)

**Source of truth:**
- Python deps → `requirements.txt`
- CLI binaries → `Dockerfile` (apt install / go install lines) + `tools/_framework/tool_versions.json` (minimum + current versions per tool)
- Template/signature DBs → per-scanner cache dir + version stamp file

**When to run:**
- Before every module forge (sanity-check the lab is current)
- Weekly via cron on the VPS (catches CVE-driven dep upgrades)
- Before every customer-facing release
- After upgrading Docker base image

**What it does NOT do:**
- Does NOT auto-`pip install --upgrade` (deterministic builds matter)
- Does NOT pull arbitrary GitHub repos (every tool must be declared first)
- Does NOT modify `requirements.txt` — that's a human decision

**Adding a new external tool:**
1. Add install line to `Dockerfile`
2. Add `{"name": "...", "min_version": "...", "check_cmd": "... --version"}` to `tools/_framework/tool_versions.json`
3. `python scripts/doctor.py` — confirm it shows green
4. Commit all three changes together

---

## Companion documents

- `VL-FOUNDRY-CHECKLIST.md` — per-forge shipping checklist (copy + tick)
- `VL-FOUNDRY-AUDIT-AGENT.md` — agent prompts for per-layer verification
- `VL-FOUNDRY-PRICING.md` — Layer 8 concrete tier→scanner mapping
- `VL-FOUNDRY-COMPLIANCE.md` — Layer 9 finding→control mapping
- `MIGRATION-GUIDE.md` — how to retrofit existing modules to VL-FOUNDRY
- `scripts/score_module.py` — objective scorer (Layer 4–7)
- `scripts/e2e_test.py` — Layer 20 full-chain verifier
- `scripts/pre_commit_score.py` — pre-commit hook (blocks scanner commits that lower the score)
- `scripts/forge_scanner.py` — scaffolds a new scanner with the 7-check skeleton
- `scripts/doctor.py` — Layer 21 dependency + tool freshness checker
- `tools/_framework/tool_versions.json` — declared min/current versions for external CLIs
- `tools/_framework/scan_state.py` — Layer 10 schema enforcer
- `tools/_framework/observability.py` — Layer 13 health tracker
- `tools/_framework/naming.py` — Layer 11 naming validator
- `tools/_framework/finding_schema.py` — runtime JSON Schema validator for findings
