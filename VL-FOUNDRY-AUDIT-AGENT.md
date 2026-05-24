# VL-FOUNDRY Audit-Agent Recipe

When you forge a new module via VL-FOUNDRY, an independent **audit agent** is
spawned at each layer gate to verify the work against the framework.

This document defines the exact prompts to use. The agent is intentionally
cold-started — it reads `VL-FOUNDRY.md` and the just-shipped files with no
context from the current build session. That independence catches gaps the
builder would rationalize away.

---

## When to spawn

Spawn ONE agent after each layer commits. Don't batch — that defeats the
independent-verification point.

```
Layer 1 commit  →  Agent #1 audits Layer 1
Layer 2 commit  →  Agent #2 audits Layer 2
... etc ...
Final commit    →  Agent #N runs the scorer + full verification
```

---

## Universal preamble (prepended to every agent prompt)

```
You are an independent audit agent for the VulnusLab VL-FOUNDRY framework.

Your job: verify that a specific module-forge layer was completed correctly,
following the rules in VL-FOUNDRY.md.

Approach:
1. Read VL-FOUNDRY.md (cold — you have NO prior context)
2. Read the files specified in this prompt
3. Compare what you see to what the framework requires
4. Return a structured pass/fail report

Bias: lean strict. False positives are cheap (builder explains). False
negatives are expensive (broken module ships). When in doubt, fail.

Output format:
  STATUS: PASS | FAIL
  PASSED CHECKS: <list>
  FAILED CHECKS: <list with exact file paths + what's missing>
  RECOMMENDATIONS: <specific edits the builder must make>
  CONFIDENCE: HIGH | MEDIUM | LOW
```

---

## Per-layer prompts

### Layer 1 — Module Role

```
{universal preamble}

LAYER: 1 (Module Role)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (focus on Layer 1 section + Module status matrix)
  - VL-FOUNDRY-CHECKLIST-<module>.md (or the in-progress checklist)
  - Any commit message containing "Layer 1" for module <module_name>

Verify:
  1. Is the customer question answered in ONE sentence?
  2. Is the pentest phase (PTES / NIST 800-115) explicitly mapped?
  3. Are 2-3 "why it exists" bullets present?
  4. Are 2-3 "what it isn't" bullets present?
  5. Is the run-ordering vs other modules documented?
  6. Has the module been added to the status matrix at the bottom of VL-FOUNDRY.md?

Fail if any of items 1-6 is missing or vague.
```

### Layer 2 — Tool Catalogue

```
{universal preamble}

LAYER: 2 (Tools)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (Layer 2 section)
  - tools/<module>/ directory listing
  - The tool catalogue table for this module (if added to VL-FOUNDRY.md)

Verify:
  1. Every .py file in tools/<module>/ (not starting with _) is in the catalogue
  2. Every catalogue entry has a corresponding .py file
  3. Each scanner has a ONE-LINE role description (not a paragraph)
  4. Tiers are defined and each scanner is in exactly one tier
  5. Tier names map to pentest workflow (not arbitrary like "tier_misc")

Fail if any orphan file or missing catalogue entry.
```

### Layer 3 — Report (PDF) — Webapp PDF is the canon

```
{universal preamble}

LAYER: 3 (Report PDF)
MODULE: <module_name>

CANON: The Webapp PDF (generatePDF in src/App.js:761) is the source of
truth for VL-FOUNDRY's PDF structure. Every module's PDF must converge
to it. When the function and VL-FOUNDRY.md disagree, the function wins.

Read these files:
  - src/App.js  (function generatePDF at line ~761 — the CANON)
  - src/App.js  (function generate<Module>Report — the SUBJECT)
  - VL-FOUNDRY.md (Layer 3 — convergence table + 17-section list)

Verify the 17 sections render in the subject's PDF generator:
   1. Cover page (black header + logo + "PENETRATION TEST REPORT")
   2. Info table (Target/Date/Classification/Authenticated/Prepared By)
   3. Trust statement ("VERIFIED VULNUSLAB" blue accent box)
   4. Key Risk Headline (color-coded box with severity tag + SLA)
   5. Executive Summary (Severity × Count × SLA × Recommendation)
   6. OWASP Top 10 Grade (A-F + per-category pass/fail)
   7. Compliance Coverage (8 frameworks)
   8. Remediation Diff (Fixed/Persisting/Novel vs previous scan)
   9. Risk Score Bar (0-100 numeric + progress bar)
  10. Severity Breakdown (horizontal bars per severity tier)
  11. Tier Coverage matrix
  12. Per-Tool Sections (one per scanner)
  13. Detailed Findings (cards: severity/CVSS/CWE/OWASP/evidence/fix)
  14. Recommendations (synthesized from findings)
  15. Verification Audit ("what each scanner probed for")
  16. Appendix (Methodology/Severity/Tools/References)
  17. Border + Footer (Report ID + Content Hash + watermark every page)

For each section: locate the corresponding block in the subject function.
Mark ✅ present / ⚠️ partial / ❌ missing. Cite the App.js line number.

Also verify 7-check DoD:
  1. Risk Score in executive summary
  2. Stacked severity bar
  3. Per-finding CVSS + CWE + OWASP
  4. Per-finding remediation
  5. Per-finding evidence_marker
  6. Verification audit table
  7. Report ID + content hash

Fail if any of the 7 checks isn't satisfied OR if >= 4 of the 17 sections
are missing/partial without an explicit waiver documented in VL-FOUNDRY.md.

When in doubt: re-read generatePDF in src/App.js. The function is canon.
```

### Layer 4 — Orchestrator

```
{universal preamble}

LAYER: 4 (Orchestrator)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (Layer 4 section)
  - endpoints/<module>_orchestrator.py
  - tools/<module>/ directory listing

Verify:
  1. <MODULE>_TOOLS_BY_TIER dict exists
  2. Number of entries in dict == number of scanner files in tools/<module>/
  3. POST /api/<module>/run_all returns NDJSON stream
  4. POST /api/<module>/run_all_buffered exists for non-streaming clients
  5. GET /api/<module>/run_all/tiers discovery endpoint exists
  6. Concurrency is configurable (default 8-12)
  7. Wall-clock timeout 240s per scanner

Run this Python in your head:
  from endpoints.<module>_orchestrator import _all_tools
  len(_all_tools())  # should equal scanner-file count

Fail if any mismatch.
```

### Layer 5 — Wordlists / AI Curation

```
{universal preamble}

LAYER: 5 (Wordlists / AI Curation)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (Layer 5 section + refresh calendar)
  - tools/_payloads/<module>/ (or shared dir if reusing)
  - tools/_gen/gen_<module>_assets.py
  - All scanner .py files in tools/<module>/

Verify:
  1. tools/_gen/gen_<module>_assets.py exists with anthropic SDK + CONFIGS
  2. Each scanner that needs curation has try/except import of wordlist
  3. Each scanner has _FALLBACK_* const for missing-wordlist case
  4. No scanner imports the wordlist without try/except (= fragile)
  5. The refresh calendar in VL-FOUNDRY.md has been updated with this module's
     wordlists + cadence

Fail if any scanner imports a wordlist without fallback (= ImportError risk).
```

### Layer 6 — Quality bar (7-check DoD)

```
{universal preamble}

LAYER: 6 (Quality bar — VL-FORGE 7-check DoD)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (Layer 6 section + the 7 checks)
  - All scanner .py files in tools/<module>/

For EACH scanner, verify the 7 checks:
  1. precheck_target() or framework equivalent (safe_get / ScanContext)
  2. Uniform shape via standard_response() / vuln_response() / run_scanner()
  3. POSITIVE finding emitted when clean
  4. severity / CVSS / CWE / OWASP fields on findings
  5. remediation field on findings
  6. evidence_marker field on findings
  7. Wall-clock cap + per-probe timeout

Then run:  python scripts/score_module.py <module> --verbose
  - Layer 6 quality bar must be >= 90%

Fail if any scanner misses >= 3 of the 7 checks.
```

### Layer 7 — Frontend

```
{universal preamble}

LAYER: 7 (Frontend integration)
MODULE: <module_name>

Read these files:
  - VL-FOUNDRY.md (Layer 7 section)
  - src/App.js (search for <MODULE>_PHASES array)
  - endpoints/<module>_orchestrator.py

Verify:
  1. <MODULE>_PHASES array exists in src/App.js
  2. Number of entries in PHASES == number in orchestrator (no orphans)
  3. Every entry has name, tool, endpoint, icon
  4. <MODULE>_SECTION_HEADERS dict exists with tier headers + colors
  5. The module appears in the main navigation (search for module name)

Fail if PHASES count != orchestrator count.
```

### Final gate — Full scorer + acid test

```
{universal preamble}

LAYER: FINAL GATE
MODULE: <module_name>

Run:
  $ python scripts/score_module.py <module> --verbose

Verify:
  1. Score >= 85
  2. All 5 layers passing or warning (no failures)
  3. ready: true in JSON output

Also verify (manual checks):
  1. VL-FOUNDRY.md status matrix has been updated with this module's score
  2. A test scan against vulnuslab.com completes successfully
  3. The PDF renders cleanly (no missing sections, no encoding glitches)
  4. Scan duration is under target SLA (Recon ≤ 2min, Vuln ≤ 5min, Webapp ≤ 90s)

Output a final SHIP / DON'T SHIP decision with reasoning.
```

---

## Anti-cheat clauses

The audit agent must REFUSE to pass if:

- The builder claims a check is "intentionally skipped" without documenting it
  in VL-FOUNDRY.md
- A scanner uses a brand-new pattern not in VL-FOUNDRY.md (= scope creep)
- The scorer was modified to make this module pass (= goalpost moving)
- VL-FOUNDRY.md was modified mid-forge to fit what was built (= circular)
- A wordlist was committed with placeholder data ("TODO" or "FIXME" entries)

If any of these is detected, the agent emits:
```
STATUS: FAIL (FRAMEWORK INTEGRITY VIOLATION)
```

---

## How to invoke

In Claude Code (this session), the builder spawns an audit agent via the
Agent tool:

```
Agent({
  subagent_type: "Explore",  // read-only is sufficient
  description: "VL-FOUNDRY Layer N audit",
  prompt: "<the layer-N prompt above with {module_name} substituted>"
})
```

The audit agent has no access to the build session's reasoning — only the
files. That's the whole point.

---

## What happens after an audit fails

```
1. Agent returns FAIL with specific gaps
2. Builder reads the gap list
3. Builder MUST address each gap before re-spawning the agent
   (no negotiation, no "but I think it's fine")
4. Builder re-commits the fix
5. New agent (cold) re-audits
6. Loop until PASS
```

If the SAME gap is rejected twice, the framework itself may have ambiguous
guidance — the builder updates VL-FOUNDRY.md to clarify, then re-runs the
audit. The framework getting more precise IS a successful outcome.
