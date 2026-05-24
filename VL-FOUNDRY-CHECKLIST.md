# Module Shipping Checklist

Copy this file when you start a new module forge. Rename to
`VL-FOUNDRY-CHECKLIST-<name>.md` and tick each box as you go.

A module **must score ≥ 85/100** via `python scripts/score_module.py <name>`
before it ships to customers. This checklist enforces the underlying
contract.

---

## Pre-flight

- [ ] Module name agreed: ____________________
- [ ] Pentest phase it covers documented (PTES / NIST 800-115 ref)
- [ ] Existing code audited (don't duplicate Recon/Vuln/Webapp coverage)
- [ ] Branch created: `forge-<modulename>`

---

## Layer 1 — Module Role

- [ ] One-sentence customer question documented in `VL-FOUNDRY.md`
- [ ] PTES/NIST phase mapping listed
- [ ] "Why it exists" bullets (2-3) documented
- [ ] "What it isn't" bullets (2-3) documented
- [ ] "When customer runs it" ordering documented

**Audit agent check:** spawn agent → ask "read VL-FOUNDRY.md and
confirm Layer 1 for <module> is complete + makes sense."

---

## Layer 2 — Tools

- [ ] All scanners catalogued in `VL-FOUNDRY.md` Layer 2 table
- [ ] Each scanner has a one-line role
- [ ] Tier grouping defined (tier1_xxx, tier2_yyy, ...)
- [ ] Tier names map to pentest workflow (not random)
- [ ] Total scanner count: ______

**Audit agent check:** "Compare `tools/<module>/` to Layer 2 table in
framework. Any scanner not in table? Any table row not in tools/?"

---

## Layer 3 — Report (PDF)

- [ ] `generate<Module>Report()` function exists in `src/App.js`
- [ ] All 9 vulntemplate blocks render (Cover / Tools / Exec / Findings /
      Compliance / Coverage / Per-tool / Audit / Appendix)
- [ ] Per-finding fields present: severity, CVSS, CWE, OWASP, remediation, evidence
- [ ] Compliance map table renders (8 frameworks)
- [ ] Report ID + content hash present
- [ ] CONFIDENTIAL footer on every page
- [ ] Risk Score (0-100) in executive summary
- [ ] Severity bar (stacked horizontal) in executive summary
- [ ] Top-3 priorities listed

**Audit agent check:** "Read generate<Module>Report() in App.js. Verify all
9 blocks present + 7-check DoD satisfied."

---

## Layer 4 — Orchestrator

- [ ] `endpoints/<module>_orchestrator.py` created
- [ ] `<MODULE>_TOOLS_BY_TIER` dict mirrors `tools/<module>/` 1:1
- [ ] Every scanner registered in a tier (no orphans)
- [ ] POST `/api/<module>/run_all` returns NDJSON stream
- [ ] POST `/api/<module>/run_all_buffered` for non-streaming clients
- [ ] GET `/api/<module>/run_all/tiers` discovery endpoint
- [ ] Concurrency cap set (default 8-12)
- [ ] Wall-clock timeout 240s per scanner
- [ ] Heartbeat every 15s
- [ ] Registered in `main.py` autodiscovery (no manual import needed)

**Audit agent check:** "Compare `_all_tools()` count to file count in
tools/<module>/. Any mismatch is a Layer 4 gap."

---

## Layer 5 — Wordlists / AI Curation

- [ ] `tools/_payloads/<module>/` directory exists (optional if reusing webapp/vuln dirs)
- [ ] `tools/_gen/gen_<module>_assets.py` committed
- [ ] All wordlists generated (you ran the gen loop on VPS)
- [ ] All wordlists committed to git
- [ ] Each scanner has `_FALLBACK_*` const for missing-wordlist case
- [ ] Each scanner imports wordlist with `try/except` (graceful fallback)
- [ ] Refresh calendar updated in framework (monthly/quarterly/annual)

**Audit agent check:** "Each scanner in tools/<module>/ — does it import
from tools._payloads.* with try/except + fallback? Any without curation
that should have it?"

---

## Layer 6 — Quality bar (VL-FORGE 7-check DoD)

For EACH scanner, verify:

- [ ] `precheck_target()` reachability guard (or framework equivalent)
- [ ] `vuln_response()` / `standard_response()` uniform output shape
- [ ] POSITIVE finding emitted when target clean
- [ ] Severity / CVSS / CWE / OWASP fields on every finding
- [ ] Remediation guidance per finding
- [ ] `evidence_marker` per finding
- [ ] Wall-clock cap + per-probe timeout

**Audit agent check:** run `python scripts/score_module.py <module> -v` and
ensure L6 quality bar passes for ≥ 90% of scanners.

### Parallel (Layer 6 sub-check)

- [ ] Network-heavy scanners use `asyncio.Semaphore` + `asyncio.gather`
- [ ] CPU-bound scanners use `ThreadPoolExecutor`
- [ ] Per-probe timeout < per-scanner wall-clock cap

**Target: ≥ 70% parallel coverage** (some scanners are inherently slow
external tools — that's OK).

---

## Layer 7 — Frontend

- [ ] `<MODULE>_PHASES` array in `src/App.js`
- [ ] Length matches orchestrator `_all_tools()` exactly
- [ ] Every scanner has: name, tool, endpoint, icon
- [ ] `<MODULE>_SECTION_HEADERS` dict with tier labels + colors
- [ ] Live scan-tile rendering shows: dot + glyph + name + badge + count + elapsed + Details
- [ ] Tier filter checkboxes work
- [ ] Module appears in main navigation

**Audit agent check:** "Count entries in PHASES array. Match to
orchestrator count exactly?"

---

## Layer 8 — Pricing tier (defer to Sell phase)

- [ ] Per-scanner plan restriction documented (or "no gate")
- [ ] Module appears in pricing tier matrix
- [ ] Quota enforcement tested (free tier hits limit cleanly)

---

## Layer 9 — Compliance mapping (defer to Sell phase)

- [ ] PCI-DSS controls mapped
- [ ] SOC2 controls mapped
- [ ] ISO 27001 controls mapped
- [ ] HIPAA controls mapped
- [ ] GDPR articles mapped
- [ ] NIST 800-53 controls mapped
- [ ] CIS v8 controls mapped
- [ ] PDF "Compliance Coverage" section renders all 7 frameworks

---

## Layer 20 — End-to-end verification

- [ ] `python scripts/e2e_test.py <module> --target=vulnuslab.com` returns exit code 0
- [ ] All 6 gates green: API reachable, POST 200, SLO met, record count sane, shape valid, ≥70% scanners dispatched
- [ ] SLO target for the module is registered in `scripts/e2e_test.py::SLO_MAX_SECONDS`
- [ ] Run repeated 3× — no flakes
- [ ] Each VULNERABLE finding passes `tools._framework.finding_schema.validate_finding`

**Audit agent check:** run e2e_test.py and confirm exit 0. Spot-check 3
random NDJSON records pass `validate_ndjson_record`.

---

## Final gate

- [ ] `python scripts/score_module.py <module>` returns **≥ 85**
- [ ] 7-check rollup shows no individual check below 70%
- [ ] `python scripts/e2e_test.py <module>` returns exit code 0 (Layer 20)
- [ ] Test scan against `vulnuslab.com` completes successfully
- [ ] PDF generated cleanly (no missing sections, no encoding glitches)
- [ ] Scan duration under target SLA (Recon ≤ 2min, Vuln ≤ 5min, Webapp ≤ 90s)
- [ ] No false positives on a known-clean target
- [ ] Real findings on a known-vulnerable target (Juice Shop / DVWA / lab)
- [ ] Module added to `VL-FOUNDRY.md` status matrix
- [ ] Commit history is clean (small, focused commits per layer)
- [ ] Pre-commit hook (`scripts/pre_commit_score.py`) green on every commit
- [ ] Pushed to `origin/main`
- [ ] Deployed on VPS (`docker compose build --no-cache backend frontend`)

---

## Sign-off

- [ ] Solo founder approval (you): ____________
- [ ] Score gate passed: ____ / 100
- [ ] Date: ____________
- [ ] Module marked READY in framework status matrix

---

## Lessons learned (fill in as you go)

What surprised you about this layer? What would you change in the framework?

| Layer | Lesson | Framework update needed? |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 20 | | |

After forging the module, commit your filled checklist + any framework
updates so the next module's forge is even smoother.
